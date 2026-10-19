
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import { randomUUID } from "node:crypto";
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

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

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

const firebaseProjectId = process.env.FIREBASE_PROJECT_ID;
const firebaseClientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY;

console.log("Firebase env check:", {
  projectIdExists: Boolean(firebaseProjectId),
  clientEmailExists: Boolean(firebaseClientEmail),
  privateKeyExists: Boolean(firebasePrivateKey),
});

if (
  firebaseProjectId &&
  firebaseClientEmail &&
  firebasePrivateKey
) {
  try {
    const firebaseApp =
      getApps().length > 0
        ? getApps()[0]
        : initializeApp({
            credential: cert({
              projectId: firebaseProjectId,
              clientEmail: firebaseClientEmail,
              privateKey: firebasePrivateKey
  .trim()
  .replace(/^["']|["']$/g, "")
  .replace(/\\n/g, "\n"),
            }),
          });

    firestore = getFirestore(firebaseApp);

    console.log("Firebase Admin initialized.");
  } catch (error) {
    console.error(
      "Firebase Admin initialization failed:",
      error.message
    );
  }
} else {
  console.warn(
    "Firebase Admin credentials are missing. " +
      "Registration API will return 503."
  );
}

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.use(cors({ origin: "*" }));

app.use(express.json({ limit: "20mb" }));

// --------------------------------------------------
// Multer
// --------------------------------------------------

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
});
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
// Shared helpers
// --------------------------------------------------

function createImageName(file) {
  const extension =
    file.mimetype === "image/png"
      ? "png"
      : file.mimetype === "image/webp"
      ? "webp"
      : "jpg";

  return `${Date.now()}-${randomUUID()}.${extension}`;
}

function getStorageFileName(url, bucket) {
  try {
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
      parsedUrl.pathname.indexOf(marker) +
        marker.length
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

async function uploadImage(req, res, bucket, label) {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No image file received.",
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

    const { data: publicUrlData } = supabase.storage
      .from(bucket)
      .getPublicUrl(data?.path || fileName);

    const publicUrl = publicUrlData?.publicUrl || "";

    if (!publicUrl) {
      return res.status(500).json({
        success: false,
        message: "Could not create public image URL.",
      });
    }

    console.log(`${label} upload successful.`);

    return res.status(200).json({
      success: true,
      message: "Image uploaded successfully.",
      url: publicUrl,
      fileName: data?.path || fileName,
    });
  } catch (error) {
    console.error(`${label} upload error:`, error);

    return res.status(500).json({
      success: false,
      message: "Image upload failed.",
    });
  }
}

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
// Health Check
// --------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Japan Job System Backend is running.",
  });
});

// --------------------------------------------------
// Attendance Student Registration
// POST /api/attendance-student/register
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

      // Only accept explicitly permitted form fields.
      // Never accept status or timestamps from the client.
      const applicationData = {
        id: studentId,
        name: data.name.trim(),

        furigana:
          typeof data.furigana === "string"
            ? data.furigana.trim()
            : "",

        nickname:
          typeof data.nickname === "string"
            ? data.nickname.trim()
            : "",

        profileImage:
          typeof data.profileImage === "string"
            ? data.profileImage
            : "",

        originalProfileImage:
          typeof data.originalProfileImage === "string"
            ? data.originalProfileImage
            : "",

        dateOfBirth:
          typeof data.dateOfBirth === "string"
            ? data.dateOfBirth
            : "",

        gender:
          typeof data.gender === "string"
            ? data.gender
            : "",

        nationality:
          typeof data.nationality === "string"
            ? data.nationality.trim()
            : "",

        phone:
          typeof data.phone === "string"
            ? data.phone.trim()
            : "",

        email:
          typeof data.email === "string"
            ? data.email.trim()
            : "",

        address:
          typeof data.address === "string"
            ? data.address.trim()
            : "",

        className: data.className.trim(),

        jlptLevel:
          typeof data.jlptLevel === "string"
            ? data.jlptLevel
            : "",

        enrollmentDate:
          typeof data.enrollmentDate === "string"
            ? data.enrollmentDate
            : "",

        guardianName:
          typeof data.guardianName === "string"
            ? data.guardianName.trim()
            : "",

        guardianPhone:
          typeof data.guardianPhone === "string"
            ? data.guardianPhone.trim()
            : "",

        emergencyContact:
          typeof data.emergencyContact === "string"
            ? data.emergencyContact.trim()
            : "",

        notes:
          typeof data.notes === "string"
            ? data.notes.trim()
            : "",

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

      await firestore.runTransaction(
        async (transaction) => {
          const registrySnapshot =
            await transaction.get(registryRef);

          if (registrySnapshot.exists) {
            const error = new Error(
              "This Student ID is already registered."
            );
            error.statusCode = 409;
            throw error;
          }

          // Check applications created before the registry existed.
          const existingQuery = applicationsRef
            .where("id", "==", studentId)
            .limit(1);

          const existingSnapshot =
            await transaction.get(existingQuery);

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

          transaction.create(
            applicationRef,
            applicationData
          );
        }
      );

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
// Attendance Student Image APIs
// --------------------------------------------------

app.post(
  "/api/upload",
  upload.single("image"),
  (req, res) =>
    uploadImage(req, res, "student-photos", "Student")
);

app.post(
  "/api/delete-images",
  (req, res) =>
    deleteImages(req, res, "student-photos", "Student")
);

app.get(
  "/api/student-photo",
  (req, res) =>
    proxyImage(req, res, "student-photos", "Student")
);

// --------------------------------------------------
// Job Student Image APIs
// --------------------------------------------------

app.post(
  "/api/job-student/upload",
  upload.single("image"),
  (req, res) =>
    uploadImage(
      req,
      res,
      "job-student-photos",
      "Job Student"
    )
);

app.post(
  "/api/job-student/delete-images",
  (req, res) =>
    deleteImages(
      req,
      res,
      "job-student-photos",
      "Job Student"
    )
);

app.get(
  "/api/job-student-photo",
  (req, res) =>
    proxyImage(
      req,
      res,
      "job-student-photos",
      "Job Student"
    )
);

// --------------------------------------------------
// Upload / JSON Error Handler
// --------------------------------------------------

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    const message =
      error.code === "LIMIT_FILE_SIZE"
        ? "Image must be 5MB or smaller."
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
  console.log(
    `Backend server running on port ${PORT}`
  );
});
