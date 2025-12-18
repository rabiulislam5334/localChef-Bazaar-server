// server.js — LocalChefBazaar (Full Production-ready)
// Node + Express + MongoDB + Firebase Admin + Stripe + JWT

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET || "");

const app = express();
const PORT = process.env.PORT || 3000;

/* -------------------------
   ENV validation
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
   Middlewares
------------------------- */
app.use(helmet());
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";
console.log("Current CORS allowed origin:", CLIENT_URL);
app.use(cors({ origin: true, credentials: true }));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use(limiter);

/* -------------------------
   Firebase Admin init
------------------------- */
try {
  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
    "utf8"
  );
  const serviceAccount = JSON.parse(decoded);

  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  console.log("Firebase Admin initialized");
} catch (error) {
  console.error("Firebase Admin error:", error.message);
  process.exit(1);
}

/* -------------------------
   MongoDB Connection
------------------------- */
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fexg8tm.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
/* -------------------------
   Helpers
------------------------- */
const catchAsync = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function toObjectId(id) {
  try {
    return new ObjectId(id);
  } catch (e) {
    return null;
  }
}

async function generateUniqueChefId(usersCollection) {
  let id,
    exists = true,
    attempts = 0;
  while (exists && attempts < 10) {
    id = "chef-" + Math.floor(1000 + Math.random() * 9000);
    exists = await usersCollection.findOne({ chefId: id });
    attempts++;
  }
  if (exists) id = "chef-" + Date.now().toString().slice(-6);
  return id;
}

/* -------------------------
   JWT & Role Middlewares
------------------------- */
const verifyFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer "))
    return res.status(401).json({ message: "Firebase token missing" });

  const idToken = authHeader.split(" ")[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decoded.email;
    req.firebase_uid = decoded.uid;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid Firebase token" });
  }
};

const verifyServerJwt = (req, res, next) => {
  const token =
    req.cookies.token ||
    (req.headers.authorization && req.headers.authorization.split(" ")[1]);
  if (!token) return res.status(401).json({ message: "Server JWT missing" });

  try {
    req.serverUser = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid server JWT" });
  }
};

const createVerifyRole = (usersCollection, role) => async (req, res, next) => {
  const email = req.decoded_email || req.serverUser?.email;
  if (!email) return res.status(401).json({ message: "Unauthorized" });

  const user = await usersCollection.findOne({ email });
  if (!user || user.role !== role)
    return res.status(403).json({ message: `Forbidden: ${role} only` });

  if (role === "chef" && user.status === "fraud")
    return res.status(403).json({ message: "Chef marked as fraud" });

  req.currentUser = user;
  next();
};

/* -------------------------
   Main Run
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

    const verifyAdmin = createVerifyRole(usersCollection, "admin");
    const verifyChef = createVerifyRole(usersCollection, "chef");

    // Indexes
    await usersCollection
      .createIndex({ email: 1 }, { unique: true })
      .catch(() => {});
    await mealsCollection.createIndex({ chefId: 1 }).catch(() => {});
    await mealsCollection.createIndex({ createdAt: -1 }).catch(() => {});
    await ordersCollection.createIndex({ userEmail: 1 }).catch(() => {});
    await reviewsCollection.createIndex({ foodId: 1 }).catch(() => {});
    console.log("Indexes ensured");

    app.get("/", (req, res) => res.send("Server running"));

    /* -------------------------
       Auth Routes
    ------------------------- */
    app.post(
      "/jwt",
      catchAsync(async (req, res) => {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: "Email required" });
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });
        const token = jwt.sign(
          { email: user.email, role: user.role, id: user._id.toString() },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );
        res.json({ token });
      })
    );

    app.post(
      "/auth/firebase-login",
      catchAsync(async (req, res) => {
        const { idToken, name, imageUrl, address } = req.body;
        if (!idToken)
          return res.status(400).json({ message: "idToken required" });

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

        if (user.status === "fraud")
          return res.status(403).json({ message: "Fraud account" });

        const token = jwt.sign(
          { email: user.email, role: user.role, id: user._id.toString() },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );
        res.cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        res.json({ success: true, user });
      })
    );

    app.post("/auth/logout", (req, res) => {
      res.clearCookie("token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
      });
      res.json({ success: true });
    });

    /* -------------------------
       Requests Routes
    ------------------------- */
    app.post(
      "/requests",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { userName, userEmail, requestType } = req.body;
        if (!userEmail || !requestType)
          return res.status(400).json({ message: "Missing fields" });
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

    app.patch(
      "/admin/requests/:id/:action",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const { id, action } = req.params;
        const request = await requestsCollection.findOne({
          _id: toObjectId(id),
        });
        if (!request)
          return res.status(404).json({ message: "Request not found" });

        if (action === "approve") {
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
          return res.json({ message: "Request approved" });
        } else if (action === "reject") {
          await requestsCollection.updateOne(
            { _id: toObjectId(id) },
            { $set: { requestStatus: "rejected" } }
          );
          return res.json({ message: "Request rejected" });
        } else {
          return res.status(400).json({ message: "Invalid action" });
        }
      })
    );

    /* -------------------------
       Meals Routes
    ------------------------- */
    app.post(
      "/meals",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const meal = req.body;
        const chefUser = req.currentUser; // verifyChef থেকে আসা full user document (DB থেকে)

        // Required fields validation
        if (!meal.foodName || !meal.price || !meal.foodImage) {
          return res.status(400).json({
            message: "Missing required fields: foodName, price, foodImage",
          });
        }

        // Safety: chefUser & _id exist check (middleware fail হলে prevent করা)
        if (!chefUser || !chefUser._id) {
          return res.status(500).json({
            message: "Chef authentication failed or user data missing",
          });
        }

        // Optional: price parse & validate
        const parsedPrice = parseFloat(meal.price);
        if (isNaN(parsedPrice) || parsedPrice <= 0) {
          return res.status(400).json({ message: "Invalid price" });
        }

        const mealDoc = {
          foodName: meal.foodName.trim(),
          foodImage: meal.foodImage,
          price: parsedPrice,
          ingredients: Array.isArray(meal.ingredients)
            ? meal.ingredients
            : meal.ingredients
            ? meal.ingredients.split(",").map((i) => i.trim())
            : [],
          estimatedDeliveryTime: meal.estimatedDeliveryTime || "30-60 minutes",
          chefExperience: meal.chefExperience || "",
          rating: 0, // always start from 0
          chefId: chefUser._id, // ← FIXED: user-এর MongoDB _id ব্যবহার করুন (unique identifier)
          chefName: chefUser.name || chefUser.displayName || "Unknown Chef",
          userEmail: chefUser.email,
          createdAt: new Date(),
        };

        const result = await mealsCollection.insertOne(mealDoc);

        // Better response: insertedId return করুন (frontend-এ useful)
        res.status(201).json({
          insertedId: result.insertedId,
          message: "Meal added successfully",
          meal: mealDoc,
        });
      })
    );

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

    app.get(
      "/meals/:id",
      catchAsync(async (req, res) => {
        const meal = await mealsCollection.findOne({
          _id: toObjectId(req.params.id),
        });
        if (!meal) return res.status(404).json({ message: "Meal not found" });
        res.json(meal);
      })
    );

    app.patch(
      "/meals/:id",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const meal = await mealsCollection.findOne({
          _id: toObjectId(req.params.id),
        });
        if (!meal || meal.userEmail !== req.serverUser.email)
          return res.status(403).json({ message: "Forbidden" });
        const updateData = { ...req.body };
        delete updateData.chefId;
        delete updateData.userEmail;
        const result = await mealsCollection.updateOne(
          { _id: toObjectId(req.params.id) },
          { $set: updateData }
        );
        res.json(result);
      })
    );

    app.delete(
      "/meals/:id",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const meal = await mealsCollection.findOne({
          _id: toObjectId(req.params.id),
        });
        if (!meal || meal.userEmail !== req.serverUser.email)
          return res.status(403).json({ message: "Forbidden" });
        await mealsCollection.deleteOne({ _id: toObjectId(req.params.id) });
        await reviewsCollection.deleteMany({ foodId: req.params.id });
        await favoritesCollection.deleteMany({ mealId: req.params.id });
        await ordersCollection.deleteMany({ foodId: req.params.id });
        res.json({ message: "Meal deleted" });
      })
    );
    app.get(
      "/chef/my-meals",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const email = req.query.email;

        if (!email) {
          return res.status(400).json({ message: "Email is required" });
        }

        // security check
        if (email !== req.serverUser.email) {
          return res.status(403).json({ message: "Forbidden" });
        }

        const meals = await mealsCollection
          .find({ userEmail: email })
          .sort({ createdAt: -1 })
          .toArray();

        res.json(meals);
      })
    );

    /* -------------------------
   Orders Routes
------------------------- */
    app.post(
      "/orders",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const userEmail = req.serverUser?.email;

        if (!userEmail) {
          return res
            .status(401)
            .json({ message: "Unauthorized: Invalid or missing token data." });
        }

        const { foodId, mealName, price, quantity, chefId, userAddress } =
          req.body;

        if (
          !foodId ||
          !mealName ||
          !price ||
          !quantity ||
          !chefId ||
          !userAddress
        ) {
          return res
            .status(400)
            .json({ message: "Missing required fields for order." });
        }

        // User existence & Fraud Check
        const user = await usersCollection.findOne({ email: userEmail });

        if (!user) {
          return res
            .status(404)
            .json({ message: "Order failed: User not found." });
        }

        if (user.status === "fraud") {
          return res.status(403).json({ message: "Fraud user" });
        }

        // Calculate Total (safe parsing)
        const finalPrice = parseFloat(price);
        const finalQuantity = parseInt(quantity, 10);

        if (isNaN(finalPrice) || isNaN(finalQuantity) || finalQuantity <= 0) {
          return res
            .status(400)
            .json({ message: "Invalid price or quantity." });
        }

        const total = finalPrice * finalQuantity;

        // Create Order Document
        const orderDoc = {
          foodId,
          mealName,
          price: finalPrice,
          quantity: finalQuantity,
          total,
          chefId,
          userAddress,
          paymentStatus: "unpaid",
          orderStatus: "pending",
          userEmail,
          orderTime: new Date(),
        };

        const result = await ordersCollection.insertOne(orderDoc);
        res
          .status(201)
          .json({ insertedId: result.insertedId, order: orderDoc });
      })
    );

    // GET my orders
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

    // GET chef order requests
    app.get(
      "/chef/order-requests",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const chefId = req.serverUser.chefId;

        if (!chefId) {
          return res.status(403).json({ message: "Chef ID not found" });
        }

        const orders = await ordersCollection
          .find({ chefId })
          .sort({ orderTime: -1 })
          .toArray();
        res.json(orders);
      })
    );

    // PATCH order status (chef only)
    app.patch(
      "/orders/:id/status",
      verifyServerJwt,
      verifyChef,
      catchAsync(async (req, res) => {
        const { newStatus } = req.body;
        const orderId = req.params.id;

        const order = await ordersCollection.findOne({
          _id: toObjectId(orderId),
        });

        if (!order) {
          return res.status(404).json({ message: "Order not found" });
        }

        const chefId = req.serverUser.chefId; // অথবা req.currentUser.chefId
        if (order.chefId !== chefId) {
          return res.status(403).json({ message: "Forbidden: Not your order" });
        }

        if (newStatus === "delivered") {
          if (order.paymentStatus !== "paid") {
            return res
              .status(400)
              .json({ message: "Payment not completed. Cannot deliver." });
          }
          if (order.orderStatus !== "accepted") {
            return res
              .status(400)
              .json({ message: "Order must be accepted first." });
          }
        }

        const result = await ordersCollection.updateOne(
          { _id: toObjectId(orderId) },
          { $set: { orderStatus: newStatus } }
        );

        res.json({ success: result.modifiedCount > 0 });
      })
    );

    // GET single order (user only)
    app.get(
      "/orders/:id",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const order = await ordersCollection.findOne({
          _id: toObjectId(req.params.id),
        });

        if (!order) {
          return res.status(404).json({ message: "Order not found" });
        }

        if (order.userEmail !== req.serverUser.email) {
          return res.status(403).json({ message: "Forbidden" });
        }

        res.json(order);
      })
    );
    // PATCH: Cancel order (User only - New Route)
    app.patch(
      "/orders/cancel/:id",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const orderId = req.params.id;
        const userEmail = req.serverUser.email;

        const order = await ordersCollection.findOne({
          _id: toObjectId(orderId),
        });

        if (!order) {
          return res.status(404).json({ message: "Order not found" });
        }

        if (order.userEmail !== userEmail) {
          return res.status(403).json({ message: "Forbidden: Not your order" });
        }

        if (order.paymentStatus === "paid") {
          return res
            .status(400)
            .json({ message: "Paid orders cannot be cancelled" });
        }

        // ৪. অর্ডার আপডেট (Status 'cancelled' করা)
        const result = await ordersCollection.updateOne(
          { _id: toObjectId(orderId) },
          { $set: { orderStatus: "cancelled" } }
        );

        res.json({ success: true, modifiedCount: result.modifiedCount });
      })
    );

    /* -------------------------
   Payments Routes
------------------------- */
    app.post(
      "/create-payment-intent",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { orderId } = req.body;

        if (!orderId) {
          return res.status(400).json({ message: "Order ID required" });
        }

        const order = await ordersCollection.findOne({
          _id: toObjectId(orderId),
          userEmail: req.serverUser.email,
          paymentStatus: "unpaid",
        });

        if (!order) {
          return res
            .status(404)
            .json({ message: "Order not found or already paid" });
        }

        const amount = Math.round(order.total * 100);

        const paymentIntent = await stripe.paymentIntents.create({
          amount,
          currency: "usd",
          payment_method_types: ["card"],
          metadata: { orderId: orderId },
        });

        res.json({ clientSecret: paymentIntent.client_secret });
      })
    );

    app.post(
      "/payments",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { orderId, transactionId, amount } = req.body;

        const order = await ordersCollection.findOne({
          _id: toObjectId(orderId),
          userEmail: req.serverUser.email,
          paymentStatus: "unpaid",
        });

        if (!order) {
          return res
            .status(400)
            .json({ message: "Invalid order or already paid" });
        }

        // Optional: amount verify
        if (parseFloat(amount) !== order.total) {
          return res.status(400).json({ message: "Amount mismatch" });
        }

        const paymentResult = await paymentsCollection.insertOne({
          orderId,
          transactionId,
          amount: parseFloat(amount),
          userEmail: req.serverUser.email,
          paymentTime: new Date(),
        });

        await ordersCollection.updateOne(
          { _id: toObjectId(orderId) },
          { $set: { paymentStatus: "paid", transactionId } }
        );

        res.json(paymentResult);
      })
    );

    app.get(
      "/payments/my",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const payments = await paymentsCollection
          .find({ userEmail: req.serverUser.email })
          .sort({ paymentTime: -1 })
          .toArray();
        res.json(payments);
      })
    );
    /* -------------------------
       Reviews Routes
    ------------------------- */
    app.post(
      "/reviews",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { foodId, rating, comment } = req.body;
        const reviewDoc = {
          foodId,
          rating: parseInt(rating),
          comment,
          reviewerEmail: req.serverUser.email,
          date: new Date(),
        };
        await reviewsCollection.insertOne(reviewDoc);
        res.json({ message: "Review added" });
      })
    );

    app.get(
      "/reviews/:foodId",
      catchAsync(async (req, res) => {
        const reviews = await reviewsCollection
          .find({ foodId: req.params.foodId })
          .sort({ date: -1 })
          .toArray();
        res.json(reviews);
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

    /* -------------------------
       Favorites Routes
    ------------------------- */
    app.post(
      "/favorites",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const { mealId } = req.body;
        const exists = await favoritesCollection.findOne({
          mealId,
          userEmail: req.serverUser.email,
        });
        if (exists)
          return res.status(409).json({ message: "Already in favorites" });
        const favoriteDoc = {
          ...req.body,
          userEmail: req.serverUser.email,
          createdAt: new Date(),
        };
        await favoritesCollection.insertOne(favoriteDoc);
        res.json({ message: "Added to favorites" });
      })
    );

    app.get(
      "/favorites/my",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const favs = await favoritesCollection
          .find({ userEmail: req.serverUser.email })
          .toArray();
        res.json(favs);
      })
    );

    app.delete(
      "/favorites/:id",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        await favoritesCollection.deleteOne({
          _id: toObjectId(req.params.id),
          userEmail: req.serverUser.email,
        });
        res.json({ message: "Removed from favorites" });
      })
    );
    /*Users Routes
------------------------- */
    app.get(
      "/users/me",
      verifyServerJwt, //
      catchAsync(async (req, res) => {
        const email = req.user?.email || req.serverUser?.email;

        if (!email) {
          // যদি email না পাওয়া যায়, তবে 401 ত্রুটি পাঠান
          return res
            .status(401)
            .json({ message: "Unauthorized: Invalid token data" });
        }

        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).json({ message: "User not found in DB" });
        }

        const { _id, ...userInfo } = user;
        res.json(userInfo);
      })
    );
    app.patch(
      "/users/me",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const allowedUpdates = {};
        const { name, address, imageUrl } = req.body;

        if (name) allowedUpdates.name = name;
        if (address) allowedUpdates.address = address;
        if (imageUrl) allowedUpdates.imageUrl = imageUrl;

        const result = await usersCollection.updateOne(
          { email: req.serverUser.email },
          { $set: allowedUpdates }
        );

        res.json(result);
      })
    );
    // GET /payments/my
    app.get("/payments/my", verifyServerJwt, async (req, res) => {
      const payments = await paymentsCollection
        .find({ userEmail: req.serverUser.email })
        .sort({ paymentTime: -1 })
        .toArray();
      res.json(payments);
    });
    app.get(
      "/users/:email/role",
      verifyServerJwt,
      catchAsync(async (req, res) => {
        const email = req.params.email;

        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).json({ role: "user" });
        }

        res.json({ role: user.role || "user" });
      })
    );

    /* -------------------------
       Admin Stats & Users
    ------------------------- */
    app.get(
      "/admin/stats",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const totalUsers = await usersCollection.countDocuments();
        const totalMeals = await mealsCollection.countDocuments();
        const [totalPayment] = await paymentsCollection
          .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
          .toArray();
        const totalPaymentAmount = totalPayment?.total || 0;
        const orderStatusCounts = await ordersCollection
          .aggregate([{ $group: { _id: "$orderStatus", count: { $sum: 1 } } }])
          .toArray();
        res.json({
          totalUsers,
          totalMeals,
          totalPaymentAmount,
          orderStatusCounts,
        });
      })
    );

    app.get(
      "/admin/users",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const users = await usersCollection.find({}).toArray();
        res.json(users);
      })
    );
    // Get all requests
    app.get(
      "/admin/requests",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const requests = await requestsCollection
          .find({})
          .sort({ requestTime: -1 })
          .toArray();

        res.json(requests);
      })
    );
    app.patch(
      "/admin/requests/:id/reject",
      verifyServerJwt,
      verifyAdmin,
      catchAsync(async (req, res) => {
        const id = req.params.id;

        const result = await requestsCollection.updateOne(
          { _id: toObjectId(id) },
          { $set: { requestStatus: "rejected" } }
        );

        res.json(result);
      })
    );

    /* -------------------------
       Server listener
    ------------------------- */
    await client.db("admin").command({ ping: 1 });
    console.log("MongoDB connected successfully!");
    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  } catch (e) {
    console.error("Server failed:", e);
    process.exit(1);
  }
}

run().catch(console.dir);
