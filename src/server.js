
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import {
  randomUUID,
  createHmac,
  timingSafeEqual,
} from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { createClient } from "@supabase/supabase-js";

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

dotenv.config();

const app = express();
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
  try {
    if (!firebaseAdminReady || getApps().length === 0) {
      return res.status(503).json({
        success: false,
        message: "Authentication service is unavailable.",
      });
    }

    const authorization = req.headers.authorization || "";
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
    console.error(
      "Authentication failed:",
      error.code || error.name
    );

    return res.status(401).json({
      success: false,
      message: "Invalid or expired authentication token.",
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

// --------------------------------------------------
// Start Server
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend server running on port ${PORT}`);
});
