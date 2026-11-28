
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import {
  randomUUID,
  createHmac,
  timingSafeEqual,
  createHash,
} from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { createClient } from "@supabase/supabase-js";
import { google } from "googleapis";
import {
  initializeApp,
  cert,
  getApps,
} from "firebase-admin/app";

import {
  getFirestore,
  FieldValue,
} from "firebase-admin/firestore";

import { getAuth } from "firebase-admin/auth";
import { getAppCheck } from "firebase-admin/app-check";

dotenv.config();

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 8080;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const IMAGE_CLEANUP_SECRET = process.env.IMAGE_CLEANUP_SECRET;
const ALLOWED_IMAGE_BUCKETS = [
  "student-photos",
  "job-student-photos",
];

// --------------------------------------------------
// Supabase
// --------------------------------------------------

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error(
    "Missing SUPABASE_URL or SUPABASE_SECRET_KEY."
  );
  process.exit(1);
}

let supabaseOrigin;

try {
  supabaseOrigin = new URL(SUPABASE_URL).origin;
} catch {
  console.error("Invalid SUPABASE_URL.");
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY
);

// --------------------------------------------------
// Firebase Admin
// --------------------------------------------------

let firestore = null;
let firebaseAdminReady = false;

const firebaseProjectId = process.env.FIREBASE_PROJECT_ID;
const firebaseClientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY;

try {
  let credential = null;

  const localServiceAccountPath = process.env.USERPROFILE
    ? path.join(
        process.env.USERPROFILE,
        "Downloads",
        "japan-job-system-6bf5b944098e.json"
      )
    : null;

  if (localServiceAccountPath) {
    try {
      const serviceAccount = JSON.parse(
        readFileSync(localServiceAccountPath, "utf8")
      );

      if (serviceAccount.project_id !== "japan-job-system") {
        throw new Error("Unexpected Firebase project ID.");
      }

      credential = cert(serviceAccount);

      console.log(
        "Using local Firebase service account JSON."
      );
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
    }
  }

  if (!credential) {
    if (
      !firebaseProjectId ||
      !firebaseClientEmail ||
      !firebasePrivateKey
    ) {
      throw new Error(
        "Firebase environment credentials are missing."
      );
    }

    const normalizedPrivateKey = firebasePrivateKey
      .replace(/\\n/g, "\n")
      .replace(/^["']|["']$/g, "")
      .trim();

    credential = cert({
      projectId: firebaseProjectId,
      clientEmail: firebaseClientEmail,
      privateKey: normalizedPrivateKey,
    });
  }

  const firebaseApp =
    getApps().length > 0
      ? getApps()[0]
      : initializeApp({
          credential,
        });

  firestore = getFirestore(firebaseApp);
  firebaseAdminReady = true;

  console.log("Firebase Admin initialized.");
} catch (error) {
  console.error(
    "Firebase Admin initialization failed:",
    error.message
  );
}

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "20mb" }));

// --------------------------------------------------
// Firebase Authentication & Authorization
// --------------------------------------------------

async function verifyFirebaseToken(req, res, next) {
 const authorization = req.headers.authorization || "";

  try {
    if (!firebaseAdminReady || getApps().length === 0) {
      return res.status(503).json({
        success: false,
        message: "Authentication service is unavailable.",
      });
    }

    const match = authorization.match(/^Bearer (.+)$/i);

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Authentication token is required.",
      });
    }

    const decodedToken = await getAuth().verifyIdToken(
      match[1]
    );

    req.authUser = decodedToken;

    return next();
  } catch (error) {
  console.error("Authentication failed:", {
  code: error.code,
  name: error.name,
  message: error.message,
  tokenType: typeof authorization.match(/^Bearer (.+)$/i)?.[1],
  tokenParts:
    authorization.match(/^Bearer (.+)$/i)?.[1]?.split(".").length,
});

    return res.status(401).json({
      success: false,
      message: "Invalid or expired authentication token.",
    });
  }
}


async function verifyAppCheckToken(req, res, next) {
  const appCheckToken = req.headers["x-firebase-appcheck"];

  if (!firebaseAdminReady || getApps().length === 0) {
    return res.status(503).json({
      success: false,
      message: "App Check service is unavailable.",
    });
  }

  if (!appCheckToken) {
    return res.status(401).json({
      success: false,
      message: "App Check token is required.",
    });
  }

  try {
    await getAppCheck().verifyToken(appCheckToken);

    return next();
  } catch (error) {
    console.error("App Check verification failed:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid App Check token.",
    });
  }
}


function requireAdmin(req, res, next) {
  if (req.authUser?.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin permission is required.",
    });
  }

  return next();
}

function requireAdminOrTeacher(req, res, next) {
  const role = req.authUser?.role;

  if (role !== "admin" && role !== "teacher") {
    return res.status(403).json({
      success: false,
      message: "Admin or Teacher permission is required.",
    });
  }

  return next();
}



// ==========================================
// CLOUDFLARE TURNSTILE VERIFICATION
// ==========================================

function normalizeEmail(email) {
  return typeof email === "string"
    ? email.trim().toLowerCase()
    : "";
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function verifyTurnstileToken(token) {
  const secret = process.env.TURNSTILE_SECRET_KEY;

  if (!secret || typeof token !== "string" || !token.trim()) {
    return false;
  }

  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          secret,
          response: token.trim(),
        }),
      }
    );

    const result = await response.json();

    return (
      response.ok &&
      result.success === true &&
      result.hostname === "japan-job-system.web.app"
    );
  } catch (error) {
    console.error("Turnstile verification error:", error.message);
    return false;
  }
}


// ==========================================
// GET USERS BY FIREBASE CUSTOM CLAIMS ROLE
// ==========================================

async function getUsersByRoles(targetRoles) {
  const matchedUsers = [];
  let pageToken;

  do {
    const result = await getAuth().listUsers(
      1000,
      pageToken
    );

    for (const user of result.users) {
      const role = user.customClaims?.role;

      if (targetRoles.includes(role)) {
        matchedUsers.push({
          uid: user.uid,
          role,
        });
      }
    }

    pageToken = result.pageToken;
  } while (pageToken);

  return matchedUsers;
}

// ==========================================
// PUBLIC JOB STUDENT REGISTRATION NOTIFICATION
// App Check protected
// ==========================================

app.post(
  "/api/public/job-student-registration-notification",
  verifyAppCheckToken,
  async (req, res) => {
    try {
      if (!firebaseAdminReady || !firestore) {
        return res.status(503).json({
          success: false,
          message: "Notification service is unavailable.",
        });
      }

      const { applicationId } = req.body;

      if (
        typeof applicationId !== "string" ||
        !applicationId.trim() ||
        applicationId.length > 150
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid application ID.",
        });
      }

      const applicationRef = firestore
        .collection("jobStudentApplications")
        .doc(applicationId);

      const applicationSnapshot = await applicationRef.get();

      if (!applicationSnapshot.exists) {
        return res.status(404).json({
          success: false,
          message: "Application not found.",
        });
      }

      const application = applicationSnapshot.data();

      if (application.applicationStatus !== "Pending") {
        return res.status(400).json({
          success: false,
          message: "Application is not pending.",
        });
      }

      const users = await getUsersByRoles([
        "admin",
        "teacher",
      ]);

      if (users.length > 450) {
        return res.status(503).json({
          success: false,
          message: "Too many notification recipients.",
        });
      }

      const result = await firestore.runTransaction(
        async (transaction) => {
          const freshApplication =
            await transaction.get(applicationRef);

          if (!freshApplication.exists) {
            throw new Error("APPLICATION_NOT_FOUND");
          }

          const freshData = freshApplication.data();

          if (freshData.notificationSentAt) {
            return false;
          }

          if (freshData.applicationStatus !== "Pending") {
            throw new Error("APPLICATION_NOT_PENDING");
          }

          const notificationRefs = users.map((user) =>
            firestore
              .collection("users")
              .doc(user.uid)
              .collection("notifications")
              .doc(applicationId)
          );

          for (let i = 0; i < users.length; i++) {
            transaction.set(notificationRefs[i], {
              title: "New Student Registration",
              message: `${freshData.name || "A student"} has submitted a new registration.`,
              type: "newStudent",
              isRead: false,
              createdAt: FieldValue.serverTimestamp(),
              createdBy: "system",
              applicationId,
            });
          }

          transaction.update(applicationRef, {
            notificationSentAt: FieldValue.serverTimestamp(),
          });

          return true;
        }
      );

      return res.status(200).json({
        success: true,
        alreadySent: !result,
        sentCount: result ? users.length : 0,
      });

    } catch (error) {
      if (error.message === "APPLICATION_NOT_FOUND") {
        return res.status(404).json({
          success: false,
          message: "Application not found.",
        });
      }

      if (error.message === "APPLICATION_NOT_PENDING") {
        return res.status(400).json({
          success: false,
          message: "Application is not pending.",
        });
      }

      console.error(
        "Public registration notification error:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Unable to send registration notification.",
      });
    }
  }
);

// ==========================================
// CREATE NOTIFICATION
// Admin only
// ==========================================

app.post(
  "/api/notifications",
  verifyFirebaseToken,
  requireAdmin,
  async (req, res) => {
    try {
      if (!firebaseAdminReady || !firestore) {
        return res.status(503).json({
          success: false,
          message: "Notification service is unavailable.",
        });
      }

      const {
        title,
        message,
        type,
      } = req.body;

      const notificationRoles = {
        newStudent: ["admin", "teacher"],
        newApplication: ["admin", "teacher"],
        attendance: ["admin", "teacher"],
        systemUpdates: ["admin"],
        userManagement: ["admin"],
      };

      const targetRoles = notificationRoles[type];

      if (
        typeof title !== "string" ||
        !title.trim() ||
        typeof message !== "string" ||
        !message.trim() ||
        !targetRoles
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid notification data.",
        });
      }

      const users = await getUsersByRoles(targetRoles);

      const batch = firestore.batch();

      for (const user of users) {
        const notificationRef = firestore
          .collection("users")
          .doc(user.uid)
          .collection("notifications")
          .doc();

        batch.set(notificationRef, {
          title: title.trim(),
          message: message.trim(),
          type,
          isRead: false,
          createdAt: FieldValue.serverTimestamp(),
          createdBy: req.authUser.uid,
        });
      }

      await batch.commit();

      return res.status(201).json({
        success: true,
        sentCount: users.length,
      });
    } catch (error) {
      console.error("Create notification error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to create notification.",
      });
    }
  }
);

// --------------------------------------------------
// Multer image upload configuration
// --------------------------------------------------

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 10 * 1024 * 1024,
  },

  fileFilter: (req, file, callback) => {
    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "image/webp",
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      return callback(
        new Error(
          "Only JPEG, PNG, and WebP images are allowed."
        )
      );
    }

    callback(null, true);
  },
});

// --------------------------------------------------
// Shared image helpers
// --------------------------------------------------

function createImageName(file) {
  const extension =
    file.mimetype === "image/png"
      ? "png"
      : file.mimetype === "image/webp"
      ? "webp"
      : "jpg";

  return `${randomUUID()}-${Date.now()}.${extension}`;
}

function createCleanupToken(bucket, filePath) {
  if (!IMAGE_CLEANUP_SECRET) {
    throw new Error(
      "IMAGE_CLEANUP_SECRET is not configured."
    );
  }

  if (!ALLOWED_IMAGE_BUCKETS.includes(bucket)) {
    throw new Error("Unsupported image bucket.");
  }

  const expiresAt = Date.now() + 30 * 60 * 1000;

  const payload = Buffer.from(
    JSON.stringify({
      bucket,
      filePath,
      expiresAt,
    })
  ).toString("base64url");

  const signature = createHmac(
    "sha256",
    IMAGE_CLEANUP_SECRET
  )
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function verifyCleanupToken(token) {
  if (
    !IMAGE_CLEANUP_SECRET ||
    typeof token !== "string"
  ) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [payload, signature] = parts;

  const expectedSignature = createHmac(
    "sha256",
    IMAGE_CLEANUP_SECRET
  )
    .update(payload)
    .digest();

  let actualSignature;

  try {
    actualSignature = Buffer.from(
      signature,
      "base64url"
    );
  } catch {
    return null;
  }

  if (
    actualSignature.length !== expectedSignature.length ||
    !timingSafeEqual(
      actualSignature,
      expectedSignature
    )
  ) {
    return null;
  }

  try {
    const decoded = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (
      !ALLOWED_IMAGE_BUCKETS.includes(decoded.bucket) ||
      typeof decoded.filePath !== "string" ||
      !decoded.filePath ||
      decoded.filePath.startsWith("/") ||
      decoded.filePath.split("/").some(
        (part) => part === "." || part === ".."
      ) ||
      !Number.isFinite(decoded.expiresAt) ||
      decoded.expiresAt <= Date.now()
    ) {
      return null;
    }

    return decoded;
  } catch {
    return null;
  }
}

async function uploadImageToSupabase(
  bucket,
  file,
  folder = ""
) {
  const filename = createImageName(file);

  const storagePath = folder
    ? `${folder}/${filename}`
    : filename;

  const { error } = await supabase.storage
    .from(bucket)
    .upload(storagePath, file.buffer, {
      contentType: file.mimetype,
      upsert: false,
    });

  if (error) {
    throw error;
  }

  const { data } = supabase.storage
    .from(bucket)
    .getPublicUrl(storagePath);

  return {
    path: storagePath,
    url: data.publicUrl,
    bucket,
  };
}

async function deleteImagesFromSupabase(
  bucket,
  imageUrls
) {
  if (
    !ALLOWED_IMAGE_BUCKETS.includes(bucket) ||
    !Array.isArray(imageUrls) ||
    imageUrls.length === 0
  ) {
    return;
  }

  const paths = imageUrls
    .filter((url) => typeof url === "string")
    .map((url) => getStorageFileName(url, bucket))
    .filter(Boolean);

  const uniquePaths = [...new Set(paths)];

  if (uniquePaths.length === 0) {
    return;
  }

  const { error } = await supabase.storage
    .from(bucket)
    .remove(uniquePaths);

  if (error) {
    throw error;
  }
}

// --------------------------------------------------
// Health check
// --------------------------------------------------

app.get("/", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Japan Job System backend is running.",
  });
});

// --------------------------------------------------
// Storage URL validation
// --------------------------------------------------

function getStorageFileName(url, bucket) {
  try {
    if (
      typeof url !== "string" ||
      !ALLOWED_IMAGE_BUCKETS.includes(bucket)
    ) {
      return null;
    }

    const parsedUrl = new URL(url);

    if (parsedUrl.origin !== supabaseOrigin) {
      return null;
    }

    const marker =
      `/storage/v1/object/public/${bucket}/`;

    if (!parsedUrl.pathname.includes(marker)) {
      return null;
    }

    const encodedName = parsedUrl.pathname.slice(
      parsedUrl.pathname.indexOf(marker) + marker.length
    );

    const fileName = decodeURIComponent(encodedName);

    if (
      !fileName ||
      fileName.startsWith("/") ||
      fileName.split("/").some(
        (part) => part === "." || part === ".."
      )
    ) {
      return null;
    }

    return fileName;
  } catch {
    return null;
  }
}

// --------------------------------------------------
// Image upload API handler
// --------------------------------------------------

async function uploadImage(req, res, bucket, label) {
  let uploadedPath = null;

  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No image file received.",
      });
    }

    if (!ALLOWED_IMAGE_BUCKETS.includes(bucket)) {
      return res.status(400).json({
        success: false,
        message: "Unsupported image bucket.",
      });
    }

    if (!IMAGE_CLEANUP_SECRET) {
      return res.status(503).json({
        success: false,
        message: "Image cleanup is not configured.",
      });
    }

    const fileName = createImageName(req.file);

    const { data, error } = await supabase.storage
      .from(bucket)
      .upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false,
      });

    if (error) {
      console.error(`${label} upload error:`, error);

      return res.status(500).json({
        success: false,
        message: "Failed to upload image.",
      });
    }

    uploadedPath = data?.path || fileName;

    const { data: publicUrlData } = supabase.storage
      .from(bucket)
      .getPublicUrl(uploadedPath);

    const publicUrl = publicUrlData?.publicUrl || "";

    if (!publicUrl) {
      await supabase.storage
        .from(bucket)
        .remove([uploadedPath]);

      return res.status(500).json({
        success: false,
        message: "Could not create public image URL.",
      });
    }

    const cleanupToken = createCleanupToken(
      bucket,
      uploadedPath
    );

    return res.status(200).json({
      success: true,
      message: "Image uploaded successfully.",
      url: publicUrl,
      fileName: uploadedPath,
      cleanupToken,
    });
  } catch (error) {
    console.error(`${label} upload error:`, error);

    if (uploadedPath) {
      try {
        await supabase.storage
          .from(bucket)
          .remove([uploadedPath]);
      } catch (cleanupError) {
        console.error(
          `${label} upload rollback failed:`,
          cleanupError.message
        );
      }
    }

    return res.status(500).json({
      success: false,
      message: "Image upload failed.",
    });
  }
}

// --------------------------------------------------
// Authenticated image deletion handler
// --------------------------------------------------

async function deleteImages(req, res, bucket, label) {
  try {
    const { urls = [] } = req.body || {};

    if (!Array.isArray(urls)) {
      return res.status(400).json({
        success: false,
        message: "urls must be an array.",
      });
    }

    const fileNames = [
      ...new Set(
        urls
          .filter(
            (url) =>
              typeof url === "string" &&
              url.trim() !== ""
          )
          .map((url) => getStorageFileName(url, bucket))
          .filter(Boolean)
      ),
    ];

    if (fileNames.length === 0) {
      return res.status(400).json({
        success: false,
        message: `No valid ${label} photo URLs found.`,
      });
    }

    const { data, error } = await supabase.storage
      .from(bucket)
      .remove(fileNames);

    if (error) {
      console.error(`${label} delete error:`, error);

      return res.status(500).json({
        success: false,
        message: "Failed to delete image(s).",
      });
    }

    return res.json({
      success: true,
      message: "Image(s) deleted successfully.",
      deleted: data || [],
    });
  } catch (error) {
    console.error(`${label} delete error:`, error);

    return res.status(500).json({
      success: false,
      message: "Image deletion failed.",
    });
  }
}

// --------------------------------------------------
// Public cleanup API
// Works for both image buckets
// --------------------------------------------------

app.post("/api/cleanup-upload", async (req, res) => {
  try {
    if (!IMAGE_CLEANUP_SECRET) {
      return res.status(503).json({
        success: false,
        message: "Image cleanup is not configured.",
      });
    }

    const { tokens } = req.body || {};

    if (
      !Array.isArray(tokens) ||
      tokens.length === 0 ||
      tokens.length > 10 ||
      !tokens.every(
        (token) => typeof token === "string"
      )
    ) {
      return res.status(400).json({
        success: false,
        message: "Valid cleanup tokens are required.",
      });
    }

    const verifiedTokens = tokens.map(
      verifyCleanupToken
    );

    if (verifiedTokens.some((item) => !item)) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired cleanup token.",
      });
    }

    // Group file paths by the bucket encoded in each signed token.
    const pathsByBucket = new Map();

    for (const item of verifiedTokens) {
      if (!pathsByBucket.has(item.bucket)) {
        pathsByBucket.set(item.bucket, new Set());
      }

      pathsByBucket.get(item.bucket).add(item.filePath);
    }

    for (const [bucket, pathSet] of pathsByBucket) {
      const filePaths = [...pathSet];

      if (filePaths.length === 0) {
        continue;
      }

      const { error } = await supabase.storage
        .from(bucket)
        .remove(filePaths);

      if (error) {
        console.error(
          `Cleanup failed for ${bucket}:`,
          error
        );

        return res.status(500).json({
          success: false,
          message: "Failed to clean up uploaded images.",
        });
      }
    }

    return res.json({
      success: true,
      message: "Uploaded images cleaned up successfully.",
    });
  } catch (error) {
    console.error("Public image cleanup error:", error);

    return res.status(500).json({
      success: false,
      message: "Image cleanup failed.",
    });
  }
});

// --------------------------------------------------
// Image proxy handler
// --------------------------------------------------

async function proxyImage(req, res, bucket, label) {
  try {
    const { url = "" } = req.query;

    if (typeof url !== "string" || !url.trim()) {
      return res.status(400).json({
        success: false,
        message: "Image URL is required.",
      });
    }

    const fileName = getStorageFileName(url, bucket);

    if (!fileName) {
      return res.status(400).json({
        success: false,
        message: `Invalid ${label} photo URL.`,
      });
    }

    const { data, error } = await supabase.storage
      .from(bucket)
      .download(fileName);

    if (error || !data) {
      return res.status(404).json({
        success: false,
        message: `${label} photo not found.`,
      });
    }

    const buffer = Buffer.from(
      await data.arrayBuffer()
    );

    res.setHeader(
      "Content-Type",
      data.type || "image/jpeg"
    );
    res.setHeader("Content-Length", buffer.length);
    res.setHeader(
      "Cache-Control",
      "public, max-age=3600"
    );

    return res.send(buffer);
  } catch (error) {
    console.error(`${label} image proxy error:`, error);

    return res.status(500).json({
      success: false,
      message: "Failed to load photo.",
    });
  }
}

// --------------------------------------------------
// Receive one image
// --------------------------------------------------

function receiveSingleImage(req, res, next) {
  upload.any()(req, res, (error) => {
    if (error) {
      return next(error);
    }

    if (req.files?.length > 1) {
      return res.status(400).json({
        success: false,
        message: "Only one image is allowed per upload.",
      });
    }

    req.file = req.files?.[0] || null;

    return next();
  });
}

// --------------------------------------------------
// Student image APIs
// --------------------------------------------------

app.post(
  "/api/upload",
  receiveSingleImage,
  (req, res) =>
    uploadImage(
      req,
      res,
      "student-photos",
      "Student"
    )
);

app.post(
  "/api/delete-images",
  verifyFirebaseToken,
  requireAdminOrTeacher,
  (req, res) =>
    deleteImages(
      req,
      res,
      "student-photos",
      "Student"
    )
);

app.get(
  "/api/student-photo",
  (req, res) =>
    proxyImage(
      req,
      res,
      "student-photos",
      "Student"
    )
);

// --------------------------------------------------
// Job student image APIs
// --------------------------------------------------

app.post(
  "/api/job-student/upload",
  receiveSingleImage,
  (req, res) =>
    uploadImage(
      req,
      res,
      "job-student-photos",
      "Job student"
    )
);

app.post(
  "/api/job-student/delete-images",
  verifyFirebaseToken,
  requireAdmin,
  (req, res) =>
    deleteImages(
      req,
      res,
      "job-student-photos",
      "Job student"
    )
);

app.get(
  "/api/job-student-photo",
  (req, res) =>
    proxyImage(
      req,
      res,
      "job-student-photos",
      "Job student"
    )
);
// --------------------------------------------------
// Dormitory registration API
// --------------------------------------------------
const normalizeNrc = (value) =>
  String(value || "")
    .normalize("NFC")
    .replace(/[၀-၉]/g, (digit) =>
      String("၀၁၂၃၄၅၆၇၈၉".indexOf(digit))
    )
    .replace(/\s+/g, "")
    .toUpperCase();

console.log("DORMITORY REGISTRATION ROUTE LOADED");
app.post("/api/dormitory/register", async (req, res) => {
  try {
    if (!firestore) {
      return res.status(503).json({
        success: false,
        message: "Registration service is not configured.",
      });
    }

    const data = req.body || {};

    const stringField = (value) =>
      typeof value === "string" ? value.trim() : "";

    const name = stringField(data.name);
    const dateOfBirth = stringField(data.dateOfBirth);
    const fatherName = stringField(data.fatherName);
    const motherName = stringField(data.motherName);
    const nrcNumber = stringField(data.nrcNumber);
    const ethnicity = stringField(data.ethnicity);
    const religion = stringField(data.religion);
    const occupation = stringField(data.occupation);
    const originRegion = stringField(data.originRegion);
    const dormitoryNumber = stringField(data.dormitoryNumber);
    const age = Number(data.age);

    if (
      !name ||
      !dateOfBirth ||
      !fatherName ||
      !motherName ||
      !nrcNumber ||
      !ethnicity ||
      !religion ||
      !occupation ||
      !originRegion ||
      !Number.isInteger(age) ||
      age < 0 ||
      !["41", "47", "51", "53", "92", "85"].includes(
        dormitoryNumber
      )
    ) {
      return res.status(400).json({
        success: false,
        message: "Please complete all required information.",
      });
    }

    const normalizedNrc = normalizeNrc(nrcNumber);

const nrcHash = createHash("sha256")
  .update(normalizedNrc)
  .digest("hex");


    const registryRef = firestore
      .collection("dormitoryNrcRegistry")
      .doc(nrcHash);

    const applicationsRef = firestore.collection(
      "dormitoryApplications"
    );

    const applicationRef = applicationsRef.doc(randomUUID());

    const applicationData = {
      id: applicationRef.id,
      name,
      age,
      dateOfBirth,
      fatherName,
      motherName,
      nrcNumber,
      ethnicity,
      religion,
      occupation,
      originRegion,
      dormitoryNumber,
      applicationStatus: "Pending",
      submittedAt: FieldValue.serverTimestamp(),
    };

    await firestore.runTransaction(async (transaction) => {
      const registrySnapshot = await transaction.get(registryRef);
      console.log("DORMITORY NRC CHECK:", {
  hash: nrcHash.slice(0, 12),
  registryExists: registrySnapshot.exists,
});
      if (registrySnapshot.exists) {
        const error = new Error("Duplicate NRC number.");
        error.statusCode = 409;
        throw error;
      }

    // Check all existing applications using normalized NRC.
const existingSnapshot = await transaction.get(applicationsRef);

const duplicateExists = existingSnapshot.docs.some((doc) => {
  const existingNrc = normalizeNrc(doc.data().nrcNumber);
  return existingNrc === normalizedNrc;
});

if (duplicateExists) {
  const error = new Error("Duplicate NRC number.");
  error.statusCode = 409;
  throw error;
}

      transaction.create(registryRef, {
        applicationId: applicationRef.id,
        createdAt: FieldValue.serverTimestamp(),
      });

      transaction.create(applicationRef, applicationData);
    });

    return res.status(201).json({
      success: true,
      message: "Registration submitted successfully.",
    });
  } catch (err) {
    if (err.statusCode === 409) {
      return res.status(409).json({
        success: false,
        message:
          "ဤ NRC နံပါတ်ဖြင့် မှတ်ပုံတင်ထားပြီးဖြစ်ပါသည်။ ထပ်မံလျှောက်ထား၍ မရပါ။",
      });
    }

    console.error("Dormitory registration error:", err);

    return res.status(500).json({
      success: false,
      message: "Registration failed. Please try again.",
    });
  }
});


// --------------------------------------------------
// Dormitory Approval + Payment Profile API
// --------------------------------------------------

app.patch(
  "/api/dormitory/:applicationId/status",
  verifyFirebaseToken,
  requireAdmin,
  async (req, res) => {
    try {
      if (!firestore) {
        return res.status(503).json({
          success: false,
          message: "Payment service is unavailable.",
        });
      }

      const { applicationId } = req.params;
      const newStatus = req.body?.applicationStatus;

      if (!applicationId || applicationId.includes("/")) {
        return res.status(400).json({
          success: false,
          message: "Invalid application ID.",
        });
      }

      if (!["Approved", "Rejected"].includes(newStatus)) {
        return res.status(400).json({
          success: false,
          message: "Invalid application status.",
        });
      }

      const applicationRef = firestore
        .collection("dormitoryApplications")
        .doc(applicationId);

      const paymentProfileRef = firestore
        .collection("paymentProfiles")
        .doc(applicationId);

      const result = await firestore.runTransaction(
        async (transaction) => {
          const applicationSnapshot =
            await transaction.get(applicationRef);

          if (!applicationSnapshot.exists) {
            const error = new Error(
              "Dormitory application not found."
            );
            error.statusCode = 404;
            throw error;
          }

          const applicationData = applicationSnapshot.data();

          if (newStatus === "Approved") {
            const profileSnapshot =
              await transaction.get(paymentProfileRef);

            if (!profileSnapshot.exists) {
              const parts = new Intl.DateTimeFormat("en-CA", {
                timeZone: "Asia/Yangon",
                year: "numeric",
                month: "2-digit",
              }).formatToParts(new Date());

              const year = parts.find(
                (part) => part.type === "year"
              ).value;

              const month = parts.find(
                (part) => part.type === "month"
              ).value;

              transaction.create(paymentProfileRef, {
                studentId: applicationId,
                studentName: applicationData.name || "",
                dormitoryNumber:
                  applicationData.dormitoryNumber || "",
                paymentCategory: null,
                monthlyFee: null,
                billingStartMonth: `${year}-${month}`,
                lastChargeMonth: null,
                checkOutDate: null,
                status: "Active",
                createdAt: FieldValue.serverTimestamp(),
                updatedAt: FieldValue.serverTimestamp(),
              });
            }
          }

          transaction.update(applicationRef, {
            applicationStatus: newStatus,
            reviewedAt: FieldValue.serverTimestamp(),
          });

          return {
            applicationStatus: newStatus,
            paymentProfileCreated:
              newStatus === "Approved",
          };
        }
      );

      return res.status(200).json({
        success: true,
        message:
          newStatus === "Approved"
            ? "Application approved and payment profile checked successfully."
            : "Application rejected successfully.",
        data: result,
      });
    } catch (error) {
      console.error("Dormitory approval API error:", error);

      return res.status(error.statusCode || 500).json({
        success: false,
        message:
          error.statusCode === 404
            ? error.message
            : "Unable to update dormitory application.",
      });
    }
  }
);



// --------------------------------------------------
// Payment Management - Student List API
// --------------------------------------------------

app.get(
  "/api/payments/students",
  verifyFirebaseToken,
  requireAdmin,
  async (req, res) => {
    try {
      if (!firestore) {
        return res.status(503).json({
          success: false,
          message: "Payment service is unavailable.",
        });
      }

      const currentMonth = getMyanmarMonth();

      const categoryFees = {
        school: 300000,
        "non-school": 200000,
      };

      const snapshot = await firestore
        .collection("paymentProfiles")
        .get();

      const students = snapshot.docs.map((doc) => {
        const data = doc.data();

        const history = Array.isArray(
          data.paymentCategoryHistory
        )
          ? [...data.paymentCategoryHistory]
          : [];

        const validHistory = history
          .filter((entry) => {
            return (
              entry &&
              typeof entry.effectiveMonth === "string" &&
              /^\d{4}-(0[1-9]|1[0-2])$/.test(
                entry.effectiveMonth
              ) &&
              Object.prototype.hasOwnProperty.call(
                categoryFees,
                entry.paymentCategory
              )
            );
          })
          .sort((a, b) =>
            a.effectiveMonth.localeCompare(b.effectiveMonth)
          );

        // Find the category effective in the current month.
        const currentChanges = validHistory.filter(
          (entry) =>
            entry.effectiveMonth <= currentMonth
        );

        const latestCurrentChange =
          currentChanges.length > 0
            ? currentChanges[currentChanges.length - 1]
            : null;

        const currentCategory = latestCurrentChange
          ? latestCurrentChange.paymentCategory
          : data.paymentCategory || null;

        const currentFee = currentCategory
          ? categoryFees[currentCategory] ??
            data.monthlyFee ??
            null
          : null;

        // Find the nearest future scheduled category.
        const upcomingChange =
          validHistory.find(
            (entry) =>
              entry.effectiveMonth > currentMonth
          ) || null;

        return {
          studentId: doc.id,
          studentName: data.studentName || "",
          dormitoryNumber: data.dormitoryNumber || "",

          paymentCategory: currentCategory,
          monthlyFee: currentFee,

          billingStartMonth:
            data.billingStartMonth || "",

          lastChargeMonth:
            data.lastChargeMonth || null,

          checkOutDate:
            data.checkOutDate || null,

          status: data.status || "Active",

          categoryHistory: validHistory,

          upcomingCategory:
            upcomingChange?.paymentCategory || null,

          upcomingMonthlyFee:
            upcomingChange
              ? categoryFees[
                  upcomingChange.paymentCategory
                ]
              : null,

          upcomingEffectiveMonth:
            upcomingChange?.effectiveMonth || null,
        };
      });

      students.sort((a, b) =>
        a.studentName.localeCompare(b.studentName)
      );

      return res.status(200).json({
        success: true,
        currentMonth,
        data: students,
      });
    } catch (error) {
      console.error(
        "Payment student list error:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Unable to load payment students.",
      });
    }
  }
);






 // --------------------------------------------------
 // Payment Management - Assign Student Category API
 // --------------------------------------------------

// --------------------------------------------------
// Payment Management - Schedule Student Category API
// --------------------------------------------------

app.patch(
  "/api/payments/students/:studentId/category",
  verifyFirebaseToken,
  requireAdmin,
  async (req, res) => {
    try {
      if (!firestore) {
        return res.status(503).json({
          success: false,
          message: "Payment service is unavailable.",
        });
      }

      const { studentId } = req.params;
      const { paymentCategory, effectiveMonth } = req.body || {};

      if (!studentId || studentId.includes("/")) {
        return res.status(400).json({
          success: false,
          message: "Invalid student ID.",
        });
      }

      const categoryFees = {
        school: 300000,
        "non-school": 200000,
      };

      if (
        !Object.prototype.hasOwnProperty.call(
          categoryFees,
          paymentCategory
        )
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid payment category.",
        });
      }

      if (
        typeof effectiveMonth !== "string" ||
        !/^\d{4}-(0[1-9]|1[0-2])$/.test(effectiveMonth)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid effective month. Use YYYY-MM.",
        });
      }

      const currentMonth = getMyanmarMonth();

      if (effectiveMonth < currentMonth) {
        return res.status(400).json({
          success: false,
          message: "Effective month cannot be in the past.",
        });
      }

      const profileRef = firestore
        .collection("paymentProfiles")
        .doc(studentId);

      const result = await firestore.runTransaction(
        async (transaction) => {
          const profileSnapshot =
            await transaction.get(profileRef);

          if (!profileSnapshot.exists) {
            const error = new Error(
              "Payment profile not found."
            );
            error.statusCode = 404;
            throw error;
          }

          const profileData = profileSnapshot.data();

          if (profileData.status !== "Active") {
            const error = new Error(
              "Only active students can be assigned a category."
            );
            error.statusCode = 400;
            throw error;
          }

          const billingStartMonth =
            profileData.billingStartMonth;

          if (
            !billingStartMonth ||
            !/^\d{4}-(0[1-9]|1[0-2])$/.test(billingStartMonth)
          ) {
            const error = new Error(
              "Invalid billing start month."
            );
            error.statusCode = 400;
            throw error;
          }

          if (effectiveMonth < billingStartMonth) {
            const error = new Error(
              "Effective month cannot be before the billing start month."
            );
            error.statusCode = 400;
            throw error;
          }

          const lastChargeMonth =
            profileData.lastChargeMonth || null;

          if (
            lastChargeMonth &&
            effectiveMonth > lastChargeMonth
          ) {
            const error = new Error(
              "Effective month cannot be after the last charge month."
            );
            error.statusCode = 400;
            throw error;
          }

          const categoryHistory = Array.isArray(
            profileData.paymentCategoryHistory
          )
            ? [...profileData.paymentCategoryHistory]
            : [];

          const newEntry = {
            effectiveMonth,
            paymentCategory,
            monthlyFee: categoryFees[paymentCategory],
            scheduledAt: new Date().toISOString(),
          };

          // Replace the entry if the same effective month already exists.
          const existingIndex = categoryHistory.findIndex(
            (entry) =>
              entry &&
              entry.effectiveMonth === effectiveMonth
          );

          if (existingIndex >= 0) {
            categoryHistory[existingIndex] = newEntry;
          } else {
            categoryHistory.push(newEntry);
          }

          categoryHistory.sort((a, b) =>
            a.effectiveMonth.localeCompare(b.effectiveMonth)
          );

          transaction.update(profileRef, {
            paymentCategoryHistory: categoryHistory,
            updatedAt: FieldValue.serverTimestamp(),
          });

          return {
            studentId,
            paymentCategory,
            monthlyFee: categoryFees[paymentCategory],
            effectiveMonth,
            paymentCategoryHistory: categoryHistory,
          };
        }
      );

      return res.status(200).json({
        success: true,
        message:
          "Payment category scheduled successfully. Existing payment records were not changed.",
        data: result,
      });
    } catch (error) {
      console.error(
        "Payment category scheduling error:",
        error
      );

      return res.status(error.statusCode || 500).json({
        success: false,
        message:
          error.statusCode === 404 ||
          error.statusCode === 400
            ? error.message
            : "Unable to schedule payment category.",
      });
    }
  }
);



// --------------------------------------------------
// Dormitory Monthly Confirmation API
// --------------------------------------------------

const getMyanmarMonth = () => {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Yangon",
    year: "numeric",
    month: "2-digit",
  }).formatToParts(new Date());

  const year = parts.find((p) => p.type === "year").value;
  const month = parts.find((p) => p.type === "month").value;

  return `${year}-${month}`;
};

// Find approved dormitory resident by NRC
app.post("/api/dormitory/monthly-lookup", async (req, res) => {
  try {
    if (!firestore) {
      return res.status(503).json({
        success: false,
        message: "Service is not configured.",
      });
    }

    const nrcNumber = String(req.body?.nrcNumber || "").trim();

    if (!nrcNumber) {
      return res.status(400).json({
        success: false,
        message: "NRC နံပါတ် ဖြည့်ပါ။",
      });
    }

    const normalizedNrc = normalizeNrc(nrcNumber);

    const nrcHash = createHash("sha256")
      .update(normalizedNrc)
      .digest("hex");

    const registrySnapshot = await firestore
      .collection("dormitoryNrcRegistry")
      .doc(nrcHash)
      .get();

    if (!registrySnapshot.exists) {
      return res.status(404).json({
        success: false,
        message: "မှတ်ပုံတင်ထားသော အချက်အလက် မတွေ့ပါ။",
      });
    }

    const applicationId = registrySnapshot.data().applicationId;

    const applicationSnapshot = await firestore
      .collection("dormitoryApplications")
      .doc(applicationId)
      .get();

    if (
      !applicationSnapshot.exists ||
      applicationSnapshot.data().applicationStatus !== "Approved"
    ) {
      return res.status(403).json({
        success: false,
        message: "အဆောင်ဝင်ခွင့် အတည်ပြုထားခြင်း မရှိသေးပါ။",
      });
    }

    const resident = applicationSnapshot.data();
    const month = getMyanmarMonth();

    const confirmationId = `${applicationId}_${month}`;

    const confirmationSnapshot = await firestore
      .collection("dormitoryMonthlyConfirmations")
      .doc(confirmationId)
      .get();

    return res.json({
      success: true,
      resident: {
        id: applicationId,
        name: resident.name,
        dormitoryNumber: resident.dormitoryNumber,
      },
      month,
      alreadyConfirmed: confirmationSnapshot.exists,
    });
  } catch (err) {
    console.error("Dormitory monthly lookup error:", err);

    return res.status(500).json({
      success: false,
      message: "အချက်အလက် ရှာဖွေရာတွင် အမှားဖြစ်နေပါသည်။",
    });
  }
});


// Confirm monthly dormitory residence
app.post("/api/dormitory/monthly-confirm", async (req, res) => {
  try {
    if (!firestore) {
      return res.status(503).json({
        success: false,
        message: "Service is not configured.",
      });
    }

    const nrcNumber = String(req.body?.nrcNumber || "").trim();

    if (!nrcNumber) {
      return res.status(400).json({
        success: false,
        message: "NRC နံပါတ် ဖြည့်ပါ။",
      });
    }

    const normalizedNrc = normalizeNrc(nrcNumber);

    const nrcHash = createHash("sha256")
      .update(normalizedNrc)
      .digest("hex");

    const registryRef = firestore
      .collection("dormitoryNrcRegistry")
      .doc(nrcHash);

    const confirmationsRef = firestore.collection(
      "dormitoryMonthlyConfirmations"
    );

    const month = getMyanmarMonth();

    await firestore.runTransaction(async (transaction) => {
      const registrySnapshot = await transaction.get(registryRef);

      if (!registrySnapshot.exists) {
        const error = new Error("Resident not found.");
        error.statusCode = 404;
        throw error;
      }

      const applicationId = registrySnapshot.data().applicationId;

      const applicationRef = firestore
        .collection("dormitoryApplications")
        .doc(applicationId);

      const applicationSnapshot = await transaction.get(applicationRef);

      if (
        !applicationSnapshot.exists ||
        applicationSnapshot.data().applicationStatus !== "Approved"
      ) {
        const error = new Error("Resident is not approved.");
        error.statusCode = 403;
        throw error;
      }

      const resident = applicationSnapshot.data();

      const confirmationRef = confirmationsRef.doc(
        `${applicationId}_${month}`
      );

      const confirmationSnapshot = await transaction.get(
        confirmationRef
      );

      if (confirmationSnapshot.exists) {
        const error = new Error("Already confirmed.");
        error.statusCode = 409;
        throw error;
      }

      transaction.create(confirmationRef, {
        studentId: applicationId,
        month,
        name: resident.name,
        dormitoryNumber: resident.dormitoryNumber,
        confirmedAt: FieldValue.serverTimestamp(),
      });
    });

    return res.json({
      success: true,
      message: "ယခုလအတွက် အဆောင်နေထိုင်မှု အတည်ပြုပြီးပါပြီ။",
      month,
    });
  } catch (err) {
    if (err.statusCode) {
      return res.status(err.statusCode).json({
        success: false,
        message:
          err.statusCode === 409
            ? "ယခုလအတွက် Confirm လုပ်ပြီးဖြစ်ပါသည်။"
            : err.statusCode === 403
              ? "အဆောင်ဝင်ခွင့် အတည်ပြုထားခြင်း မရှိသေးပါ။"
              : "မှတ်ပုံတင်ထားသော အချက်အလက် မတွေ့ပါ။",
      });
    }

    console.error("Dormitory monthly confirmation error:", err);

    return res.status(500).json({
      success: false,
      message: "Confirmation failed. Please try again.",
    });
  }
});


// --------------------------------------------------
// Attendance student registration API
// --------------------------------------------------

app.post(
  "/api/attendance-student/register",
  async (req, res) => {
    try {
      if (!firestore) {
        return res.status(503).json({
          success: false,
          message: "Registration service is not configured.",
        });
      }

      const data = req.body || {};

      const studentId = String(data.id || "")
        .trim()
        .toUpperCase();

      if (!/^KB-\d+$/.test(studentId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid Student ID.",
        });
      }

      if (
        typeof data.name !== "string" ||
        !data.name.trim() ||
        typeof data.className !== "string" ||
        !data.className.trim()
      ) {
        return res.status(400).json({
          success: false,
          message: "Student name and class are required.",
        });
      }

      const stringField = (value) =>
        typeof value === "string" ? value.trim() : "";

      const applicationData = {
        id: studentId,
        name: stringField(data.name),
        furigana: stringField(data.furigana),
        nickname: stringField(data.nickname),
        profileImage: stringField(data.profileImage),
        originalProfileImage: stringField(
          data.originalProfileImage
        ),
        dateOfBirth: stringField(data.dateOfBirth),
        gender: stringField(data.gender),
        nationality: stringField(data.nationality),
        phone: stringField(data.phone),
        email: stringField(data.email),
        address: stringField(data.address),
        className: stringField(data.className),
        jlptLevel: stringField(data.jlptLevel),
        enrollmentDate: stringField(data.enrollmentDate),
        guardianName: stringField(data.guardianName),
        guardianPhone: stringField(data.guardianPhone),
        emergencyContact: stringField(data.emergencyContact),
        notes: stringField(data.notes),
        applicationStatus: "Pending",
        submittedAt: FieldValue.serverTimestamp(),
      };

      const registryRef = firestore
        .collection("attendanceStudentIdRegistry")
        .doc(studentId);

      const applicationsRef = firestore.collection(
        "attendanceStudentApplications"
      );

      const applicationRef = applicationsRef.doc(
        randomUUID()
      );

      await firestore.runTransaction(async (transaction) => {
        const registrySnapshot = await transaction.get(
          registryRef
        );

        if (registrySnapshot.exists) {
          const error = new Error(
            "This Student ID is already registered."
          );
          error.statusCode = 409;
          throw error;
        }

        const existingQuery = applicationsRef
          .where("id", "==", studentId)
          .limit(1);

        const existingSnapshot = await transaction.get(
          existingQuery
        );

        if (!existingSnapshot.empty) {
          const error = new Error(
            "This Student ID is already registered."
          );
          error.statusCode = 409;
          throw error;
        }

        transaction.create(registryRef, {
          id: studentId,
          applicationId: applicationRef.id,
          createdAt: FieldValue.serverTimestamp(),
        });

        transaction.create(applicationRef, applicationData);
      });

      console.log("Registration submitted:", studentId);

      return res.status(201).json({
        success: true,
        message: "Registration submitted successfully.",
        applicationId: applicationRef.id,
      });
    } catch (error) {
      if (error.statusCode === 409) {
        return res.status(409).json({
          success: false,
          message: error.message,
        });
      }

      console.error("Registration API error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to submit registration.",
      });
    }
  }
);
// =====================================================
// ATTENDANCE ANALYTICS — ADMIN / TEACHER ONLY
// =====================================================

const ANALYTICS_SPREADSHEET_ID =
  "1apOx658D0-fIiQ0ttlRtQq9fGp2elNiN8KsY0A0Yeb4";

const ANALYTICS_SHEETS = [
  "Summary_Aung_Phyo_Khant1",
  "Summary_Aung_Phyo_Khant2",
  "Summary_Sis Too1",
  "Summary_Sis Too2",
  "Summary_Han",
];

function isHolidayRed(color) {
  if (!color) return false;

  const red = color.red ?? 0;
  const green = color.green ?? 0;
  const blue = color.blue ?? 0;

  return red > 0.8 && green < 0.4 && blue < 0.4;
}

async function getAnalyticsSheetsClient() {
  const { GoogleAuth } = google.auth;
  const fs = await import("node:fs/promises");
  const path = await import("node:path");

  const localKeyPath = path.join(
    process.env.USERPROFILE || "",
    "Downloads",
    "japan-job-system-6bf5b944098e.json"
  );

  let auth;

  try {
    await fs.access(localKeyPath);

    auth = new GoogleAuth({
      keyFile: localKeyPath,
      scopes: ["https://www.googleapis.com/auth/spreadsheets.readonly"],
    });
  } catch {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = process.env.FIREBASE_PRIVATE_KEY
      ?.replace(/\\n/g, "\n")
      .replace(/^["']|["']$/g, "")
      .trim();

    if (!projectId || !clientEmail || !privateKey) {
      throw new Error("Google Sheets service-account credentials are missing.");
    }

    auth = new GoogleAuth({
      credentials: {
        project_id: projectId,
        client_email: clientEmail,
        private_key: privateKey,
      },
      scopes: ["https://www.googleapis.com/auth/spreadsheets.readonly"],
    });
  }

  return google.sheets({
    version: "v4",
    auth,
  });
}

app.get(
  "/api/attendance-analytics",
  verifyFirebaseToken,
  requireAdminOrTeacher,
  async (req, res) => {
    try {
      const sheetsApi = await getAnalyticsSheetsClient();

      const result = await sheetsApi.spreadsheets.get({
        spreadsheetId: ANALYTICS_SPREADSHEET_ID,
        includeGridData: true,
        ranges: ANALYTICS_SHEETS.map((name) => `'${name}'!A:ZZ`),
        fields:
          "sheets(properties(title),data(rowData(values(formattedValue,effectiveValue,effectiveFormat(backgroundColor)))))",
      });

      const sheets = (result.data.sheets || []).map((sheet) => {
        const rows = sheet.data?.[0]?.rowData || [];
        const values = rows.map((row) =>
          (row.values || []).map((cell) => {
            if (cell.formattedValue !== undefined) {
              return cell.formattedValue;
            }

            const value = cell.effectiveValue;

            if (!value) return "";

            if (value.stringValue !== undefined) return value.stringValue;
            if (value.numberValue !== undefined) return value.numberValue;
            if (value.boolValue !== undefined) return value.boolValue;

            return "";
          })
        );

        const header = rows[0]?.values || [];
        const holidayDates = new Set();

        header.forEach((cell, columnIndex) => {
          const date = values[0]?.[columnIndex];

          if (!date) return;

          const columnIsRed = rows.some((row) => {
            const color =
              row.values?.[columnIndex]?.effectiveFormat?.backgroundColor;

            return isHolidayRed(color);
          });

          if (columnIsRed) {
            holidayDates.add(String(date).trim());
          }
        });

        return {
          name: sheet.properties?.title || "",
          rows: values,
          holidayDates: [...holidayDates],
        };
      });

      res.json({
        success: true,
        sheets,
      });
    } catch (error) {
      console.error("Attendance analytics error:", error);

      res.status(500).json({
        success: false,
        message: "Unable to load attendance analytics.",
      });
    }
  }
);

// --------------------------------------------------
// Error Handler
// --------------------------------------------------

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    const message =
      error.code === "LIMIT_FILE_SIZE"
        ? "Image must be 10MB or smaller."
        : error.message;

    return res.status(400).json({
      success: false,
      message,
    });
  }

  if (
    error.message ===
    "Only JPEG, PNG, and WebP images are allowed."
  ) {
    return res.status(400).json({
      success: false,
      message: error.message,
    });
  }

  console.error("Unhandled server error:", error);

  return res.status(500).json({
    success: false,
    message: "Internal server error.",
  });
});


/* ==========================================
   NOTIFICATION APIs
========================================== */

// Get current user's notifications
app.get(
  "/api/notifications",
  verifyFirebaseToken,
  requireAdminOrTeacher,
  async (req, res) => {
    try {
      const userId = req.authUser.uid;

      const snapshot = await firestore
        .collection("users")
        .doc(userId)
        .collection("notifications")
        .orderBy("createdAt", "desc")
        .limit(50)
        .get();

      const notifications = snapshot.docs.map((doc) => ({
        id: doc.id,
        ...doc.data(),
      }));

      res.json({
        success: true,
        notifications,
      });
    } catch (error) {
      console.error("Get notifications error:", error);

      res.status(500).json({
        success: false,
        message: "Unable to load notifications.",
      });
    }
  }
);


// Mark one notification as read
app.patch(
  "/api/notifications/:id/read",
  verifyFirebaseToken,
  requireAdminOrTeacher,
  async (req, res) => {
    try {
      const userId = req.authUser.uid;
      const notificationId = req.params.id;

      const notificationRef = firestore
        .collection("users")
        .doc(userId)
        .collection("notifications")
        .doc(notificationId);

      await firestore.runTransaction(async (transaction) => {
        const doc = await transaction.get(notificationRef);

        if (!doc.exists) {
          throw new Error("NOTIFICATION_NOT_FOUND");
        }

        transaction.update(notificationRef, {
          isRead: true,
          readAt: FieldValue.serverTimestamp(),
        });
      });

      res.json({
        success: true,
        message: "Notification marked as read.",
      });
    } catch (error) {
      if (error.message === "NOTIFICATION_NOT_FOUND") {
        return res.status(404).json({
          success: false,
          message: "Notification not found.",
        });
      }

      console.error("Mark notification read error:", error);

      res.status(500).json({
        success: false,
        message: "Unable to update notification.",
      });
    }
  }
);


// Mark all notifications as read
app.patch(
  "/api/notifications/read-all",
  verifyFirebaseToken,
  requireAdminOrTeacher,
  async (req, res) => {
    try {
      const userId = req.authUser.uid;

      const snapshot = await firestore
        .collection("users")
        .doc(userId)
        .collection("notifications")
        .where("isRead", "==", false)
        .limit(450)
        .get();

      if (!snapshot.empty) {
        const batch = firestore.batch();

        snapshot.docs.forEach((doc) => {
          batch.update(doc.ref, {
            isRead: true,
            readAt: FieldValue.serverTimestamp(),
          });
        });

        await batch.commit();
      }

      res.json({
        success: true,
        updatedCount: snapshot.size,
      });
    } catch (error) {
      console.error("Mark all notifications read error:", error);

      res.status(500).json({
        success: false,
        message: "Unable to update notifications.",
      });
    }
  }
);

// ==========================================
// CREATE PUBLIC JOB STUDENT DRAFT
// ==========================================

async function createJobStudentDraft(req, res) {
  try {
    if (!firebaseAdminReady || !firestore) {
      return res.status(503).json({
        success: false,
        message: "Database is not available.",
      });
    }

    const email = normalizeEmail(req.body?.email);
    const category = req.body?.category;
    const turnstileToken = req.body?.turnstileToken;

    const allowedCategories = [
      "Caregiver",
      "Restaurant",
      "Factory",
      "Hotel",
      "Construction",
      "Agriculture",
      "Cleaning",
      "Industrial Product Manufacturing",
      "Other",
    ];

    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address.",
      });
    }

    if (!allowedCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: "Invalid job category.",
      });
    }

    const isHuman =
      await verifyTurnstileToken(turnstileToken);

    if (!isHuman) {
      return res.status(403).json({
        success: false,
        message: "Human verification failed.",
      });
    }

    const lockId = createHash("sha256")
  .update(`${email}::${category}`)
  .digest("hex");

const lockRef = firestore
  .collection("jobStudentApplicationLocks")
  .doc(lockId);

    const counterRef = firestore
      .collection("systemCounters")
      .doc("jobStudentApplication");

    const draftRef = firestore
      .collection("jobStudentDrafts")
      .doc();

    const pendingQuery = firestore
      .collection("jobStudentApplications")
      .where("desiredJob", "==", category);

    const approvedQuery = firestore
      .collection("jobStudents")
      .where("desiredJob", "==", category);

    const updateToken = randomUUID();

    const tokenHash = createHash("sha256")
      .update(updateToken)
      .digest("hex");

    const result = await firestore.runTransaction(
      async (transaction) => {
        const [
  counterSnapshot,
  pendingSnapshot,
  approvedSnapshot,
  lockSnapshot,
] = await Promise.all([
  transaction.get(counterRef),
  transaction.get(pendingQuery),
  transaction.get(approvedQuery),
  transaction.get(lockRef),
]);

        const duplicatePending =
          pendingSnapshot.docs.some(
            (item) =>
              normalizeEmail(item.data().email) === email
          );

        const duplicateApproved =
          approvedSnapshot.docs.some(
            (item) =>
              normalizeEmail(item.data().email) === email
          );

          const existingLockExpiresAt =
  lockSnapshot.data()?.expiresAt || 0;

const hasActiveLock =
  lockSnapshot.exists &&
  Number(existingLockExpiresAt) > Date.now();

if (
  duplicatePending ||
  duplicateApproved ||
  hasActiveLock
) {
  throw new Error("DUPLICATE_APPLICATION");
}

        if (!counterSnapshot.exists) {
          throw new Error("COUNTER_NOT_INITIALIZED");
        }

        const currentValue =
          counterSnapshot.data()?.value;

        if (
          !Number.isSafeInteger(currentValue) ||
          currentValue < 0
        ) {
          throw new Error("INVALID_COUNTER_VALUE");
        }

        const nextValue = currentValue + 1;

        const studentId =
          `KB${String(nextValue).padStart(7, "0")}`;

        const referenceId = `REF-${studentId}`;

        transaction.set(lockRef, {
  email,
  desiredJob: category,
  draftId: draftRef.id,
  expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
  createdAt: FieldValue.serverTimestamp(),
});

        transaction.create(draftRef, {
          email,
          desiredJob: category,
          id: studentId,
          referenceId,
          tokenHash,
          revision: 0,
          applicationType: "new",
          status: "Draft",
          createdAt: FieldValue.serverTimestamp(),
          expiresAt: new Date(
            Date.now() + 7 * 24 * 60 * 60 * 1000
          ).toISOString(),
        });

        transaction.update(counterRef, {
          value: nextValue,
          updatedAt: FieldValue.serverTimestamp(),
        });

        return {
          studentId,
          referenceId,
          draftId: draftRef.id,
        };
      }
    );

    return res.status(201).json({
      success: true,
      ...result,
      updateToken,
    });

  } catch (error) {
    if (error.message === "DUPLICATE_APPLICATION") {
      return res.status(409).json({
        success: false,
        message:
          "An application with this email and job category already exists.",
      });
    }

    if (
      error.message === "COUNTER_NOT_INITIALIZED" ||
      error.message === "INVALID_COUNTER_VALUE"
    ) {
      return res.status(503).json({
        success: false,
        message: "Student ID counter is not configured correctly.",
      });
    }

    console.error(
      "Create job student draft error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to create application draft.",
    });
  }
}

// --------------------------------------------------

// --------------------------------------------------
// JOB STUDENT REGISTRATION API
// Sequential KB ID Allocation
// --------------------------------------------------

async function createAdminJobStudentApplication(req, res) {
  try {
    if (!firebaseAdminReady || !firestore) {
      return res.status(503).json({
        success: false,
        message: "Database is not available.",
      });
    }

    const applicationData = req.body?.applicationData;

    if (
      !applicationData ||
      typeof applicationData !== "object" ||
      Array.isArray(applicationData)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid application data.",
      });
    }

    const email = normalizeEmail(applicationData.email);
    const turnstileToken = req.body?.turnstileToken;

    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address.",
      });
    }

    // Verify Cloudflare Turnstile
    const isHuman = await verifyTurnstileToken(turnstileToken);

    if (!isHuman) {
      return res.status(403).json({
        success: false,
        message:
          "Human verification failed. Please complete the security check again.",
      });
    }

    const counterRef = firestore
      .collection("systemCounters")
      .doc("jobStudentApplication");

    const applicationRef = firestore
      .collection("jobStudentApplications")
      .doc();

    const result = await firestore.runTransaction(async (transaction) => {
      const counterSnapshot = await transaction.get(counterRef);

      if (!counterSnapshot.exists) {
        throw new Error("COUNTER_NOT_INITIALIZED");
      }

      const currentValue = counterSnapshot.data()?.value;

      if (!Number.isSafeInteger(currentValue) || currentValue < 0) {
        throw new Error("INVALID_COUNTER_VALUE");
      }

      const nextValue = currentValue + 1;

      const studentId = `KB${String(nextValue).padStart(7, "0")}`;

      const newApplication = {
        ...applicationData,
        email,
        id: studentId,
        applicationStatus: "Pending",
        submittedAt: new Date().toISOString(),
      };

      delete newApplication.notificationSentAt;
      delete newApplication.firestoreId;

      transaction.create(applicationRef, newApplication);

      transaction.update(counterRef, {
        value: nextValue,
        updatedAt: FieldValue.serverTimestamp(),
      });

      return {
        studentId,
        applicationId: applicationRef.id,
      };
    });

    return res.status(201).json({
      success: true,
      ...result,
    });
  } catch (error) {
    if (
      error.message === "COUNTER_NOT_INITIALIZED" ||
      error.message === "INVALID_COUNTER_VALUE"
    ) {
      return res.status(503).json({
        success: false,
        message: "Student ID counter is not configured correctly.",
      });
    }

    console.error("Create job student application error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to submit application.",
    });
  }
}

async function revokeJobStudentDraft(req, res) {
  try {
    if (!firebaseAdminReady || !firestore) {
      return res.status(503).json({
        success: false,
        message: "Database is not available.",
      });
    }

    const draftId = req.body?.draftId;

    if (
      typeof draftId !== "string" ||
      !draftId.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Valid draft ID is required.",
      });
    }

    const draftRef = firestore
      .collection("jobStudentDrafts")
      .doc(draftId.trim());

    await firestore.runTransaction(async (transaction) => {
      const draftSnapshot = await transaction.get(draftRef);

      if (!draftSnapshot.exists) {
        throw new Error("DRAFT_NOT_FOUND");
      }

      const draft = draftSnapshot.data();

      if (draft.status === "Revoked") {
        return;
      }

      const lockId = createHash("sha256")
        .update(
          `${normalizeEmail(draft.email)}::${draft.desiredJob}`
        )
        .digest("hex");

      const lockRef = firestore
        .collection("jobStudentApplicationLocks")
        .doc(lockId);

      const lockSnapshot = await transaction.get(lockRef);

      transaction.update(draftRef, {
        status: "Revoked",
        tokenHash: FieldValue.delete(),
        revokedAt: FieldValue.serverTimestamp(),
      });

      if (
        lockSnapshot.exists &&
        lockSnapshot.data()?.draftId === draftId.trim()
      ) {
        transaction.delete(lockRef);
      }
    });

    return res.status(200).json({
      success: true,
      message: "Application refill access has been revoked.",
    });

  } catch (error) {
    if (error.message === "DRAFT_NOT_FOUND") {
      return res.status(404).json({
        success: false,
        message: "Application draft was not found.",
      });
    }

    console.error("Revoke job student draft error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to revoke application access.",
    });
  }
}

async function lookupPublicJobStudentRefill(req, res) {
  try {
    if (!firebaseAdminReady || !firestore) {
      return res.status(503).json({
        success: false,
        message: "Database is not available.",
      });
    }

    const referenceId = req.body?.referenceId;
    const email = normalizeEmail(req.body?.email);
    const category = req.body?.category;
    const updateToken = req.body?.updateToken;
    const xmlRevision = req.body?.revision;

    if (
      typeof referenceId !== "string" ||
      !referenceId.trim() ||
      !isValidEmail(email) ||
      typeof category !== "string" ||
      typeof updateToken !== "string" ||
      !updateToken.trim() ||
      !Number.isSafeInteger(xmlRevision) ||
      xmlRevision < 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid refill verification data.",
      });
    }

    const allowedCategories = [
      "Caregiver",
      "Restaurant",
      "Factory",
      "Hotel",
      "Construction",
      "Agriculture",
      "Cleaning",
      "Industrial Product Manufacturing",
      "Other",
    ];

    if (!allowedCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: "Invalid job category.",
      });
    }

    const draftQuery = await firestore
      .collection("jobStudentDrafts")
      .where("referenceId", "==", referenceId.trim())
      .limit(1)
      .get();

    if (draftQuery.empty) {
      return res.status(404).json({
        success: false,
        message: "Application reference was not found.",
      });
    }

    const draftSnapshot = draftQuery.docs[0];
    const draft = draftSnapshot.data();

    if (
      draft.status !== "Submitted" ||
      !draft.tokenHash ||
      normalizeEmail(draft.email) !== email ||
      draft.desiredJob !== category
    ) {
      return res.status(403).json({
        success: false,
        message: "Application refill access is invalid or revoked.",
      });
    }

    const submittedTokenHash = createHash("sha256")
      .update(updateToken)
      .digest();

    const storedTokenHash = Buffer.from(
      draft.tokenHash,
      "hex"
    );

    if (
      storedTokenHash.length !== submittedTokenHash.length ||
      !timingSafeEqual(
        storedTokenHash,
        submittedTokenHash
      )
    ) {
      return res.status(403).json({
        success: false,
        message: "Invalid application security token.",
      });
    }

    let applicationSnapshot = await firestore
      .collection("jobStudents")
      .doc(String(draft.id))
      .get();

    if (!applicationSnapshot.exists) {
      const pendingQuery = await firestore
        .collection("jobStudentApplications")
        .where("draftId", "==", draftSnapshot.id)
        .limit(1)
        .get();

      if (!pendingQuery.empty) {
        applicationSnapshot = pendingQuery.docs[0];
      }
    }

    if (!applicationSnapshot.exists) {
      return res.status(404).json({
        success: false,
        message: "The original application no longer exists.",
      });
    }

    const applicationData = applicationSnapshot.data();
    const currentRevision = Number(
      applicationData.revision || 0
    );

    if (currentRevision !== xmlRevision) {
      return res.status(409).json({
        success: false,
        code: "REVISION_CONFLICT",
        message:
          "This XML file is outdated. The application has been updated since this file was saved.",
        currentRevision,
      });
    }

    return res.status(200).json({
      success: true,
      referenceId: draft.referenceId,
      studentId: draft.id,
      revision: currentRevision,
      applicationData,
    });

  } catch (error) {
    console.error(
      "Lookup public job student refill error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to verify refill application.",
    });
  }
}

async function submitPublicJobStudentRefill(req, res) {
  try {
    if (!firebaseAdminReady || !firestore) {
      return res.status(503).json({
        success: false,
        message: "Database is not available.",
      });
    }

    const referenceId = req.body?.referenceId;
    const email = normalizeEmail(req.body?.email);
    const category = req.body?.category;
    const updateToken = req.body?.updateToken;
    const expectedRevision = req.body?.revision;
    const applicationData = req.body?.applicationData;

    if (
      typeof referenceId !== "string" ||
      !referenceId.trim() ||
      !isValidEmail(email) ||
      typeof category !== "string" ||
      typeof updateToken !== "string" ||
      !updateToken.trim() ||
      !Number.isSafeInteger(expectedRevision) ||
      expectedRevision < 0 ||
      !applicationData ||
      typeof applicationData !== "object" ||
      Array.isArray(applicationData)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid refill submission data.",
      });
    }

    const allowedCategories = [
      "Caregiver",
      "Restaurant",
      "Factory",
      "Hotel",
      "Construction",
      "Agriculture",
      "Cleaning",
      "Industrial Product Manufacturing",
      "Other",
    ];

    if (!allowedCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: "Invalid job category.",
      });
    }

    if (
      normalizeEmail(applicationData.email) !== email ||
      applicationData.desiredJob !== category
    ) {
      return res.status(400).json({
        success: false,
        message: "Email or job category does not match.",
      });
    }

    const draftQuery = await firestore
      .collection("jobStudentDrafts")
      .where("referenceId", "==", referenceId.trim())
      .limit(1)
      .get();

    if (draftQuery.empty) {
      return res.status(404).json({
        success: false,
        message: "Application reference was not found.",
      });
    }

    const draftSnapshot = draftQuery.docs[0];
    const draftRef = draftSnapshot.ref;

    const submittedTokenHash = createHash("sha256")
      .update(updateToken)
      .digest();

    const storedTokenHash = Buffer.from(
      draftSnapshot.data().tokenHash || "",
      "hex"
    );

    if (
      storedTokenHash.length !== submittedTokenHash.length ||
      !timingSafeEqual(
        storedTokenHash,
        submittedTokenHash
      )
    ) {
      return res.status(403).json({
        success: false,
        message: "Invalid application security token.",
      });
    }

    const approvedRef = firestore
      .collection("jobStudents")
      .doc(String(draftSnapshot.data().id));

    const pendingQuery = firestore
      .collection("jobStudentApplications")
      .where("draftId", "==", draftSnapshot.id)
      .limit(1);

    const result = await firestore.runTransaction(
      async (transaction) => {
        const currentDraftSnapshot =
          await transaction.get(draftRef);

        if (!currentDraftSnapshot.exists) {
          throw new Error("DRAFT_NOT_FOUND");
        }

        const draft = currentDraftSnapshot.data();

        const currentTokenHash = Buffer.from(
          draft.tokenHash || "",
          "hex"
        );

        if (
          draft.status !== "Submitted" ||
          normalizeEmail(draft.email) !== email ||
          draft.desiredJob !== category ||
          currentTokenHash.length !== submittedTokenHash.length ||
          !timingSafeEqual(
            currentTokenHash,
            submittedTokenHash
          )
        ) {
          throw new Error("INVALID_REFILL_ACCESS");
        }

        const approvedSnapshot =
          await transaction.get(approvedRef);

        let targetRef = approvedRef;
        let targetSnapshot = approvedSnapshot;

        if (!approvedSnapshot.exists) {
          const pendingSnapshot =
            await transaction.get(pendingQuery);

          if (pendingSnapshot.empty) {
            throw new Error("APPLICATION_NOT_FOUND");
          }

          targetSnapshot = pendingSnapshot.docs[0];
          targetRef = targetSnapshot.ref;
        }

        const currentApplication = targetSnapshot.data();
        const currentRevision = Number(
          currentApplication.revision || 0
        );

        if (currentRevision !== expectedRevision) {
          throw new Error("REVISION_CONFLICT");
        }


const updatedApplication = {
  ...currentApplication,
  ...applicationData,

  id: draft.id,
  draftId: draftRef.id,
  referenceId: draft.referenceId,
  email,
  desiredJob: category,



  applicationType: "refill",
  revision: currentRevision + 1,
  applicationStatus:
    currentApplication.applicationStatus ||
    (approvedSnapshot.exists ? "Approved" : "Pending"),

  updatedAt: new Date().toISOString(),
};

// Preserve original admin-managed fields
if (
  Object.prototype.hasOwnProperty.call(
    currentApplication,
    "status"
  )
) {
  updatedApplication.status = currentApplication.status;
} else {
  delete updatedApplication.status;
}

if (
  Object.prototype.hasOwnProperty.call(
    currentApplication,
    "createdDate"
  )
) {
  updatedApplication.createdDate =
    currentApplication.createdDate;
} else {
  delete updatedApplication.createdDate;
}


        delete updatedApplication.firestoreId;
        delete updatedApplication.tokenHash;
        delete updatedApplication.updateToken;
        delete updatedApplication.notificationSentAt;

        transaction.set(targetRef, updatedApplication, {
          merge: false,
        });

        transaction.update(draftRef, {
          revision: currentRevision + 1,
          lastRefilledAt: FieldValue.serverTimestamp(),
        });

        return {
          studentId: draft.id,
          referenceId: draft.referenceId,
          revision: currentRevision + 1,
          applicationStatus: updatedApplication.applicationStatus,
        };
      }
    );

    return res.status(200).json({
      success: true,
      ...result,
    });

  } catch (error) {
    if (error.message === "DRAFT_NOT_FOUND") {
      return res.status(404).json({
        success: false,
        message: "Application draft was not found.",
      });
    }

    if (error.message === "APPLICATION_NOT_FOUND") {
      return res.status(404).json({
        success: false,
        message: "The original application no longer exists.",
      });
    }

    if (error.message === "INVALID_REFILL_ACCESS") {
      return res.status(403).json({
        success: false,
        message: "Application refill access is invalid or revoked.",
      });
    }

    if (error.message === "REVISION_CONFLICT") {
      return res.status(409).json({
        success: false,
        code: "REVISION_CONFLICT",
        message: "Application data has changed. Please load the latest XML before submitting.",
      });
    }

    console.error(
      "Submit public job student refill error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to update refill application.",
    });
  }
}


async function submitPublicJobStudentApplication(req, res) {
  try {
    if (!firebaseAdminReady || !firestore) {
      return res.status(503).json({
        success: false,
        message: "Database is not available.",
      });
    }

    const applicationData = req.body?.applicationData;
    const draftId = req.body?.draftId;
    const updateToken = req.body?.updateToken;

    if (
      !applicationData ||
      typeof applicationData !== "object" ||
      Array.isArray(applicationData)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid application data.",
      });
    }

    if (
      typeof draftId !== "string" ||
      !draftId.trim() ||
      typeof updateToken !== "string" ||
      !updateToken.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Application verification is missing.",
      });
    }

    const email = normalizeEmail(applicationData.email);
    const category = applicationData.desiredJob;

    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address.",
      });
    }

    const allowedCategories = [
      "Caregiver",
      "Restaurant",
      "Factory",
      "Hotel",
      "Construction",
      "Agriculture",
      "Cleaning",
      "Industrial Product Manufacturing",
      "Other",
    ];

    if (!allowedCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: "Invalid job category.",
      });
    }

    const draftRef = firestore
      .collection("jobStudentDrafts")
      .doc(draftId);

    const lockId = createHash("sha256")
      .update(`${email}::${category}`)
      .digest("hex");

    const lockRef = firestore
      .collection("jobStudentApplicationLocks")
      .doc(lockId);

    const applicationRef = firestore
      .collection("jobStudentApplications")
      .doc();

    const submittedTokenHash = createHash("sha256")
      .update(updateToken)
      .digest();

    const result = await firestore.runTransaction(
      async (transaction) => {
        const [draftSnapshot, lockSnapshot] =
          await Promise.all([
            transaction.get(draftRef),
            transaction.get(lockRef),
          ]);

        if (!draftSnapshot.exists || !lockSnapshot.exists) {
          throw new Error("DRAFT_NOT_FOUND");
        }

        const draft = draftSnapshot.data();
        const lock = lockSnapshot.data();

        const storedTokenHash = Buffer.from(
          draft.tokenHash || "",
          "hex"
        );

        if (
          storedTokenHash.length !== submittedTokenHash.length ||
          !timingSafeEqual(
            storedTokenHash,
            submittedTokenHash
          )
        ) {
          throw new Error("INVALID_UPDATE_TOKEN");
        }

        if (
          draft.status !== "Draft" ||
          lock.draftId !== draftId ||
          normalizeEmail(draft.email) !== email ||
          draft.desiredJob !== category ||
          draft.expiresAt <= new Date().toISOString() ||
          Number(lock.expiresAt) <= Date.now()
        ) {
          throw new Error("DRAFT_EXPIRED_OR_INVALID");
        }

        const newApplication = {
  ...applicationData,
  email,
  desiredJob: category,
  id: draft.id,
  draftId: draftRef.id,
  referenceId: draft.referenceId,
  applicationType: "new",
  revision: draft.revision || 0,
  applicationStatus: "Pending",
  submittedAt: new Date().toISOString(),
};

        delete newApplication.notificationSentAt;
        delete newApplication.firestoreId;
        delete newApplication.tokenHash;
        delete newApplication.updateToken;

        transaction.create(applicationRef, newApplication);

        transaction.update(draftRef, {
          status: "Submitted",
          applicationId: applicationRef.id,
          submittedAt: FieldValue.serverTimestamp(),
        });

        transaction.update(lockRef, {
          status: "Submitted",
          submittedAt: FieldValue.serverTimestamp(),
          expiresAt: FieldValue.delete(),
        });

        return {
          studentId: draft.id,
          referenceId: draft.referenceId,
          applicationId: applicationRef.id,
        };
      }
    );

    return res.status(201).json({
      success: true,
      ...result,
    });

  } catch (error) {
    if (error.message === "DRAFT_NOT_FOUND") {
      return res.status(404).json({
        success: false,
        message: "Application draft was not found.",
      });
    }

    if (error.message === "INVALID_UPDATE_TOKEN") {
      return res.status(403).json({
        success: false,
        message: "Invalid application security token.",
      });
    }

    if (error.message === "DRAFT_EXPIRED_OR_INVALID") {
      return res.status(409).json({
        success: false,
        message: "Application draft has expired or is no longer valid.",
      });
    }

    console.error(
      "Submit public job student application error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to submit application.",
    });
  }
}

// Public job student draft: App Check protected
app.post(
  "/api/public/job-student-drafts",
  verifyAppCheckToken,
  createJobStudentDraft
);

// Public refill lookup: App Check protected
app.post(
  "/api/public/job-student-refill/lookup",
  verifyAppCheckToken,
  lookupPublicJobStudentRefill
);

// Public refill submit: App Check protected
app.post(
  "/api/public/job-student-refill/submit",
  verifyAppCheckToken,
  submitPublicJobStudentRefill
);

// Public registration: App Check protected
app.post(
  "/api/public/job-student-applications",
  verifyAppCheckToken,
  submitPublicJobStudentApplication
);

// Admin registration: Firebase Auth + Admin/Teacher role
app.post(
  "/api/admin/job-student-applications",
  verifyFirebaseToken,
  requireAdminOrTeacher,
  createAdminJobStudentApplication
);

// Revoke public application refill access
app.post(
  "/api/admin/job-student-drafts/revoke",
  verifyFirebaseToken,
  requireAdminOrTeacher,
  revokeJobStudentDraft
);
// Start Server
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend server running on port ${PORT}`);
});
