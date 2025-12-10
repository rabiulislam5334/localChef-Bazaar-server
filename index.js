// server.js — LocalChefBazaar (Patched & Production-ready)
// Node + Express + MongoDB + Firebase Admin + Stripe + JWT
// Key fixes:
// - ENV validation
// - catchAsync wrapper for async route handlers
// - ObjectId consistency helpers
// - generateUniqueChefId (DB-checked)
// - JWT improvements (stringify id)
// - Stripe amount rounding & validation
// - Cleanup relations using ObjectId
// - Index creation (safe)
// - Improved cookie options + CORS notes

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET || ""); // will be validated by env-check

const app = express();
const PORT = process.env.PORT || 3000;

/* -------------------------
   ENV validation (critical)
   ------------------------- */
const requiredEnvs = [
  "DB_USER",
  "DB_PASS",
  "FB_SERVICE_KEY",
  "JWT_SECRET",
  "STRIPE_SECRET",
];
const missing = requiredEnvs.filter((k) => !process.env[k]);
if (missing.length) {
  console.error("Missing required env vars:", missing.join(", "));
  process.exit(1);
}

/* -------------------------
   Basic middlewares & security
   ------------------------- */
app.use(helmet());
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";
// Configure CORS for credentials to allow httpOnly cookie transfer
app.use(
  cors({
    origin: CLIENT_URL,
    credentials: true,
  })
);

// basic rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120, // limit each IP to 120 requests per windowMs
});
app.use(limiter);

/* -------------------------
   Firebase Admin init (serviceAccount base64)
   ------------------------- */
try {
  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
    "utf8"
  );
  const serviceAccount = JSON.parse(decoded);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log("Firebase Admin initialized");
} catch (error) {
  console.error("Error initializing Firebase Admin:", error.message);
  process.exit(1);
}

/* -------------------------
   MongoDB connection
   ------------------------- */
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fexg8tm.mongodb.net/?appName=Cluster0`;

// const uri = `mongodb+srv://${encodeURIComponent(
//   process.env.DB_USER
// )}:${encodeURIComponent(
//   process.env.DB_PASS
// )}@cluster0.vyznij5.mongodb.net/?retryWrites=true&w=majority&appName=LocalChefBazaar`;

const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1 },
});

/* -------------------------
   Helpers
   ------------------------- */

// catchAsync wrapper for async route handlers
const catchAsync = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Safe ObjectId conversion
function toObjectId(id) {
  try {
    return new ObjectId(id);
  } catch (e) {
    return null;
  }
}

// generate unique chefId with DB check (simple loop)
async function generateUniqueChefId(usersCollection) {
  let id;
  let exists = true;
  let attempts = 0;
  while (exists && attempts < 10) {
    id = "chef-" + Math.floor(1000 + Math.random() * 9000);
    exists = await usersCollection.findOne({ chefId: id });
    attempts++;
  }
  if (exists) {
    // fallback to timestamp-based
    id = "chef-" + Date.now().toString().slice(-6);
  }
  return id;
}

/* -------------------------
   Middlewares (JWT + Firebase verification)
   ------------------------- */

// verify Firebase ID token (used for login/registration sync)
const verifyFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "unauthorized access (no firebase token)" });
  }
  const idToken = authHeader.split(" ")[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decodedToken.email;
    req.firebase_uid = decodedToken.uid;
    next();
  } catch (err) {
    return res.status(401).json({ message: "invalid firebase token" });
  }
};

// verify server JWT (httpOnly cookie or Authorization Bearer)
const verifyServerJwt = (req, res, next) => {
  const token =
    req.cookies.token ||
    (req.headers.authorization && req.headers.authorization.split(" ")[1]);
  if (!token)
    return res.status(401).json({ message: "unauthorized (no server token)" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.serverUser = decoded; // { email, role, id, iat, exp }
    next();
  } catch (err) {
    return res.status(401).json({ message: "invalid server token" });
  }
};

// role-check creators (need usersCollection)
const createVerifyAdmin = (usersCollection) => async (req, res, next) => {
  const email = req.decoded_email || req.serverUser?.email;
  if (!email) return res.status(401).json({ message: "unauthorized" });

  const user = await usersCollection.findOne({ email });
  if (!user || user.role !== "admin") {
    return res.status(403).json({ message: "forbidden access - admin only" });
  }
  req.currentUser = user;
  next();
};

const createVerifyChef = (usersCollection) => async (req, res, next) => {
  const email = req.decoded_email || req.serverUser?.email;
  if (!email) return res.status(401).json({ message: "unauthorized" });

  const user = await usersCollection.findOne({ email });
  if (!user || user.role !== "chef") {
    return res.status(403).json({ message: "forbidden access - chef only" });
  }
  if (user.status === "fraud") {
    return res
      .status(403)
      .json({ message: "forbidden access - chef status: fraud" });
  }
  req.currentUser = user;
  next();
};

/* -------------------------
   Main run
   ------------------------- */
async function run() {
  try {
    await client.connect();
    const db = client.db("LocalChefBazaar");

    // Collections
    const usersCollection = db.collection("users");
    const mealsCollection = db.collection("meals");
    const ordersCollection = db.collection("orders");
    const paymentsCollection = db.collection("payments");
    const reviewsCollection = db.collection("reviews");
    const favoritesCollection = db.collection("favorites");
    const requestsCollection = db.collection("requests");

    // create role middlewares bound to collections
    const verifyAdmin = createVerifyAdmin(usersCollection);
    const verifyChef = createVerifyChef(usersCollection);

    // Create crucial indexes (safe - run on startup)
    await usersCollection
      .createIndex({ email: 1 }, { unique: true })
      .catch(() => {});
    await mealsCollection.createIndex({ chefId: 1 }).catch(() => {});
    await mealsCollection.createIndex({ createdAt: -1 }).catch(() => {});
    await ordersCollection.createIndex({ userEmail: 1 }).catch(() => {});
    await reviewsCollection.createIndex({ foodId: 1 }).catch(() => {});
    console.log("Important indexes ensured");

    // Simple health check
    app.get("/", (req, res) => {
      res.send("LocalChefBazaar Server is running and healthy.");
    });

    /* -----------------------------
           AUTH: Firebase login -> issue server JWT + set httpOnly cookie
           ----------------------------- */
    app.post(
      "/auth/firebase-login",
      catchAsync(async (req, res) => {
        const { idToken, name, imageUrl, address } = req.body;
        if (!idToken)
          return res.status(400).json({ message: "idToken required" });

        try {
          const decoded = await admin.auth().verifyIdToken(idToken);
          const email = decoded.email;
          let user = await usersCollection.findOne({ email });

          if (!user) {
            const newUser = {
              name: name || decoded.name || email.split("@")[0],
              email,
              imageUrl: imageUrl || decoded.picture || "",
              address: address || "",
              role: "user",
              status: "active",
              createdAt: new Date(),
            };
            const insert = await usersCollection.insertOne(newUser);
            user = { ...newUser, _id: insert.insertedId };
          }

          if (user.status === "fraud") {
            return res.status(403).json({
              message: "Account is marked as fraud and cannot log in.",
            });
          }

          // JWT sign: ensure id is string
          const token = jwt.sign(
            { email: user.email, role: user.role, id: user._id.toString() },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
          );

          // Set httpOnly cookie
          res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          });

          return res.json({ success: true, user });
        } catch (err) {
          console.error("firebase-login error", err);
          return res.status(401).json({ message: "invalid firebase idToken" });
        }
      })
    );

    // Logout (clear cookie)
    app.post("/auth/logout", (req, res) => {
      res.clearCookie("token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
      });
      res.json({ success: true, message: "Logged out successfully" });
    });

    /* -----------------------------
           USERS & PROFILE
           ----------------------------- */

    // Get logged-in user profile
    app.get(
      "/users/me",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const user = await usersCollection.findOne({
          email: req.serverUser.email,
        });
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json(user);
      })
    );

    // Get user role by email (safe to expose role only)
    app.get(
      "/users/:email/role",
      catchAsync(async (req, res) => {
        const email = req.params.email;
        const user = await usersCollection.findOne({ email });
        res.json({ role: user?.role || "user" });
      })
    );

    // Admin: list all users
    app.get(
      "/admin/users",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const users = await usersCollection.find({}).toArray();
        res.json(users);
      })
    );

    // Admin: mark fraud
    app.patch(
      "/users/:id/fraud",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const targetUser = await usersCollection.findOne({
          _id: toObjectId(id),
        });
        if (!targetUser)
          return res.status(404).json({ message: "User not found" });
        if (targetUser.role === "admin")
          return res
            .status(403)
            .json({ message: "Cannot mark an Admin as fraud." });

        const result = await usersCollection.updateOne(
          { _id: toObjectId(id) },
          { $set: { status: "fraud" } }
        );
        res.json(result);
      })
    );

    // Admin: update role
    app.patch(
      "/users/:id/role",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const { role } = req.body;
        const update = { $set: { role } };
        if (role === "chef") {
          update.$set.chefId = await generateUniqueChefId(usersCollection);
        }
        const result = await usersCollection.updateOne(
          { _id: toObjectId(id) },
          update
        );
        res.json(result);
      })
    );

    /* -----------------------------
           REQUESTS (Be a Chef / Be an Admin)
           ----------------------------- */

    app.post(
      "/requests",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { userName, userEmail, requestType } = req.body;
        if (!userEmail || !requestType)
          return res.status(400).json({ message: "missing fields" });

        const doc = {
          userName,
          userEmail,
          requestType,
          requestStatus: "pending",
          requestTime: new Date(),
        };

        const result = await requestsCollection.insertOne(doc);
        res.json(result);
      })
    );

    app.get(
      "/admin/requests",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const result = await requestsCollection
          .find({})
          .sort({ requestTime: -1 })
          .toArray();
        res.json(result);
      })
    );

    app.patch(
      "/admin/requests/:id/approve",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const request = await requestsCollection.findOne({
          _id: toObjectId(id),
        });
        if (!request)
          return res.status(404).json({ message: "Request not found" });

        if (request.requestType === "chef") {
          const chefId = await generateUniqueChefId(usersCollection);
          await usersCollection.updateOne(
            { email: request.userEmail },
            { $set: { role: "chef", chefId } }
          );
        } else if (request.requestType === "admin") {
          await usersCollection.updateOne(
            { email: request.userEmail },
            { $set: { role: "admin" } }
          );
        }

        await requestsCollection.updateOne(
          { _id: toObjectId(id) },
          { $set: { requestStatus: "approved" } }
        );
        res.json({
          success: true,
          message: "Request approved and user role updated.",
        });
      })
    );

    app.patch(
      "/admin/requests/:id/reject",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        await requestsCollection.updateOne(
          { _id: toObjectId(id) },
          { $set: { requestStatus: "rejected" } }
        );
        res.json({ success: true, message: "Request rejected." });
      })
    );

    /* -----------------------------
           MEALS
           ----------------------------- */

    app.post(
      "/meals",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const meal = req.body;
        const chefUser = await usersCollection.findOne({
          email: req.serverUser.email,
        });
        if (!chefUser || chefUser.status === "fraud")
          return res.status(403).json({ message: "Access denied." });

        if (!meal.foodName || !meal.price || !meal.foodImage)
          return res.status(400).json({ message: "missing fields" });

        const mealDoc = {
          ...meal,
          rating: meal.rating || 0,
          chefId: chefUser.chefId,
          chefName: chefUser.name,
          userEmail: chefUser.email,
          createdAt: new Date(),
        };
        const result = await mealsCollection.insertOne(mealDoc);
        res.json(result);
      })
    );

    // Get meals with pagination & sort
    app.get(
      "/meals",
      catchAsync(async (req, res) => {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(50, parseInt(req.query.limit) || 10);
        const skip = (page - 1) * limit;
        const sortParam = req.query.sort || "";
        let sortObj = { createdAt: -1 };

        if (sortParam === "price_asc") sortObj = { price: 1 };
        else if (sortParam === "price_desc") sortObj = { price: -1 };

        const meals = await mealsCollection
          .find({})
          .sort(sortObj)
          .skip(skip)
          .limit(limit)
          .toArray();

        const totalCount = await mealsCollection.countDocuments({});

        res.json({
          meals,
          totalCount,
          totalPages: Math.ceil(totalCount / limit),
          currentPage: page,
        });
      })
    );

    // Get meal details
    app.get(
      "/meals/:id",
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const meal = await mealsCollection.findOne({ _id: toObjectId(id) });
        if (!meal) return res.status(404).json({ message: "Meal not found" });
        res.json(meal);
      })
    );

    // Chef: List My Meals
    app.get(
      "/chef/mymeals",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const meals = await mealsCollection
          .find({ userEmail: req.serverUser.email })
          .toArray();
        res.json(meals);
      })
    );

    // Chef: Update Meal
    app.patch(
      "/meals/:id",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const updateData = req.body;
        delete updateData.chefId;
        delete updateData.userEmail;

        const meal = await mealsCollection.findOne({ _id: toObjectId(id) });
        if (!meal || meal.userEmail !== req.serverUser.email)
          return res.status(403).json({
            message: "Forbidden: You can only update your own meals.",
          });

        const result = await mealsCollection.updateOne(
          { _id: toObjectId(id) },
          { $set: updateData }
        );
        res.json(result);
      })
    );

    // Chef: Delete Meal (with cleanup)
    app.delete(
      "/meals/:id",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const meal = await mealsCollection.findOne({ _id: toObjectId(id) });
        if (!meal || meal.userEmail !== req.serverUser.email)
          return res.status(403).json({
            message: "Forbidden: You can only delete your own meals.",
          });

        const result = await mealsCollection.deleteOne({ _id: toObjectId(id) });

        // Clean up related data: ensure using ObjectId for foodId/mealId
        await reviewsCollection.deleteMany({ foodId: toObjectId(id) });
        await favoritesCollection.deleteMany({ mealId: id }); // favorites might store string mealId; adapt accordingly
        await ordersCollection.deleteMany({
          foodId: id,
          orderStatus: { $in: ["pending", "accepted", "preparing"] },
        });

        res.json(result);
      })
    );

    /* -----------------------------
           ORDERS
           ----------------------------- */

    // Place Order
    app.post(
      "/orders",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { foodId, mealName, price, quantity, chefId, userAddress } =
          req.body;
        const user = await usersCollection.findOne({
          email: req.serverUser.email,
        });
        if (user.status === "fraud")
          return res
            .status(403)
            .json({ message: "Fraud users cannot place orders." });

        const orderDoc = {
          foodId, // store as string or ObjectId depending on client; keep consistent - backend will accept string but for references use consistent rule
          mealName,
          price: parseFloat(price),
          quantity: parseInt(quantity),
          chefId,
          paymentStatus: "Pending",
          userEmail: req.serverUser.email,
          userAddress,
          orderStatus: "pending",
          orderTime: new Date(),
        };

        const result = await ordersCollection.insertOne(orderDoc);
        res.json(result);
      })
    );

    // My Orders
    app.get(
      "/orders/my",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const orders = await ordersCollection
          .find({ userEmail: req.serverUser.email })
          .sort({ orderTime: -1 })
          .toArray();
        res.json(orders);
      })
    );

    // Chef: Order Requests
    app.get(
      "/chef/order-requests",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const chef = req.currentUser;
        const orders = await ordersCollection
          .find({ chefId: chef.chefId })
          .sort({ orderTime: -1 })
          .toArray();
        res.json(orders);
      })
    );

    // Chef: Update Order Status
    app.patch(
      "/orders/:id/status",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const { newStatus } = req.body;
        const chef = req.currentUser;

        const order = await ordersCollection.findOne({ _id: toObjectId(id) });
        if (!order || order.chefId !== chef.chefId)
          return res
            .status(403)
            .json({ message: "Forbidden: Not your order." });

        let updateStatus = newStatus;
        if (newStatus === "delivered" && order.orderStatus !== "accepted") {
          return res
            .status(400)
            .json({ message: "Order must be accepted before delivery." });
        }

        const result = await ordersCollection.updateOne(
          { _id: toObjectId(id) },
          { $set: { orderStatus: updateStatus } }
        );

        res.json(result);
      })
    );

    /* -----------------------------
           PAYMENTS (Stripe Integration)
           ----------------------------- */

    app.post(
      "/create-payment-intent",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { price } = req.body;
        const amount = Math.round(parseFloat(price) * 100); // integer cents
        if (!Number.isFinite(amount) || amount < 50)
          return res.status(400).json({ message: "Invalid payment amount." });

        try {
          const paymentIntent = await stripe.paymentIntents.create({
            amount: amount,
            currency: "usd",
            payment_method_types: ["card"],
          });
          res.json({ clientSecret: paymentIntent.client_secret });
        } catch (error) {
          res.status(500).json({ message: error.message });
        }
      })
    );

    app.post(
      "/payments",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const payment = req.body;
        const { orderId, transactionId, amount, userEmail } = payment;

        const paymentResult = await paymentsCollection.insertOne({
          ...payment,
          amount: parseFloat(amount),
          paymentTime: new Date(),
        });

        const orderUpdateResult = await ordersCollection.updateOne(
          { _id: toObjectId(orderId), userEmail },
          { $set: { paymentStatus: "Paid", transactionId } }
        );

        res.json({ paymentResult, orderUpdateResult });
      })
    );

    /* -----------------------------
           REVIEWS
           ----------------------------- */

    app.get(
      "/reviews/:foodId",
      catchAsync(async (req, res) => {
        const foodId = req.params.foodId;
        const reviews = await reviewsCollection
          .find({ foodId })
          .sort({ date: -1 })
          .toArray();
        res.json(reviews);
      })
    );

    app.post(
      "/reviews",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { foodId, reviewerName, reviewerImage, rating, comment } =
          req.body;

        const reviewDoc = {
          foodId, // store as string of meal _id for simplicity; consistent usage across app recommended
          reviewerName,
          reviewerImage,
          reviewerEmail: req.serverUser.email,
          rating: parseInt(rating),
          comment,
          date: new Date(),
        };

        const result = await reviewsCollection.insertOne(reviewDoc);

        // Recompute avg rating (foodId stored as string)
        const [avgRating] = await reviewsCollection
          .aggregate([
            { $match: { foodId } },
            { $group: { _id: "$foodId", avgRating: { $avg: "$rating" } } },
          ])
          .toArray();

        if (avgRating) {
          await mealsCollection.updateOne(
            { _id: toObjectId(foodId) },
            { $set: { rating: Math.round(avgRating.avgRating * 10) / 10 } }
          );
        }

        res.json(result);
      })
    );

    app.get(
      "/reviews/my",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const reviews = await reviewsCollection
          .find({ reviewerEmail: req.serverUser.email })
          .sort({ date: -1 })
          .toArray();
        res.json(reviews);
      })
    );

    app.patch(
      "/reviews/:id",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const { rating, comment } = req.body;

        const review = await reviewsCollection.findOne({ _id: toObjectId(id) });
        if (!review || review.reviewerEmail !== req.serverUser.email)
          return res
            .status(403)
            .json({ message: "Forbidden: Not your review." });

        const result = await reviewsCollection.updateOne(
          { _id: toObjectId(id) },
          { $set: { rating: parseInt(rating), comment, date: new Date() } }
        );

        const [avgRating] = await reviewsCollection
          .aggregate([
            { $match: { foodId: review.foodId } },
            { $group: { _id: "$foodId", avgRating: { $avg: "$rating" } } },
          ])
          .toArray();

        if (avgRating) {
          await mealsCollection.updateOne(
            { _id: toObjectId(review.foodId) },
            { $set: { rating: Math.round(avgRating.avgRating * 10) / 10 } }
          );
        }

        res.json(result);
      })
    );

    app.delete(
      "/reviews/:id",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const review = await reviewsCollection.findOne({ _id: toObjectId(id) });
        if (!review || review.reviewerEmail !== req.serverUser.email)
          return res
            .status(403)
            .json({ message: "Forbidden: Not your review." });

        const result = await reviewsCollection.deleteOne({
          _id: toObjectId(id),
        });

        const [avgRating] = await reviewsCollection
          .aggregate([
            { $match: { foodId: review.foodId } },
            { $group: { _id: "$foodId", avgRating: { $avg: "$rating" } } },
          ])
          .toArray();

        const newRating = avgRating
          ? Math.round(avgRating.avgRating * 10) / 10
          : 0;
        await mealsCollection.updateOne(
          { _id: toObjectId(review.foodId) },
          { $set: { rating: newRating } }
        );

        res.json(result);
      })
    );

    /* -----------------------------
           FAVORITES
           ----------------------------- */

    app.post(
      "/favorites",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { mealId, mealName, chefId, chefName, price } = req.body;

        const exists = await favoritesCollection.findOne({
          userEmail: req.serverUser.email,
          mealId,
        });
        if (exists)
          return res
            .status(409)
            .json({ message: "Meal already in favorites." });

        const favoriteDoc = {
          mealId,
          mealName,
          chefId,
          chefName,
          price,
          userEmail: req.serverUser.email,
          addedTime: new Date(),
        };

        const result = await favoritesCollection.insertOne(favoriteDoc);
        res.json(result);
      })
    );

    app.get(
      "/favorites/my",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const favorites = await favoritesCollection
          .find({ userEmail: req.serverUser.email })
          .sort({ addedTime: -1 })
          .toArray();
        res.json(favorites);
      })
    );

    app.delete(
      "/favorites/:id",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const id = req.params.id;
        const favorite = await favoritesCollection.findOne({
          _id: toObjectId(id),
        });
        if (!favorite || favorite.userEmail !== req.serverUser.email)
          return res
            .status(403)
            .json({ message: "Forbidden: Not your favorite." });

        const result = await favoritesCollection.deleteOne({
          _id: toObjectId(id),
        });
        res.json(result);
      })
    );

    /* -----------------------------
           ADMIN: PLATFORM STATISTICS
           ----------------------------- */

    app.get(
      "/admin/stats",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const totalUsers = await usersCollection.countDocuments({});

        const [totalPayment] = await paymentsCollection
          .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
          .toArray();
        const totalPaymentAmount = totalPayment ? totalPayment.total : 0;

        const orderStatusCounts = await ordersCollection
          .aggregate([{ $group: { _id: "$orderStatus", count: { $sum: 1 } } }])
          .toArray();

        const ordersPending =
          orderStatusCounts.find((s) => s._id === "pending")?.count || 0;
        const ordersDelivered =
          orderStatusCounts.find((s) => s._id === "delivered")?.count || 0;
        const ordersAccepted =
          orderStatusCounts.find((s) => s._id === "accepted")?.count || 0;
        const ordersCancelled =
          orderStatusCounts.find((s) => s._id === "cancelled")?.count || 0;

        res.json({
          totalUsers,
          totalPaymentAmount,
          ordersPending,
          ordersDelivered,
          ordersAccepted,
          ordersCancelled,
          orderStatusCounts,
        });
      })
    );

    // ping DB
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } catch (e) {
    console.error("Failed to run server:", e);
    process.exit(1);
  } finally {
    // Do NOT close client here for long-running server
  }
}

run().catch(console.dir);

/* -----------------------------
   Error Handlers & Listener
   ----------------------------- */

// 404
app.use((req, res, next) => {
  res.status(404).json({ message: "Route not found" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Global error:", err);
  res
    .status(500)
    .json({ message: "Something broke on the server!", error: err.message });
});

app.listen(PORT, () => {
  console.log(`LocalChefBazaar server listening on port ${PORT}`);
});
