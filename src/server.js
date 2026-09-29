import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 8080;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY =
  process.env.SUPABASE_SECRET_KEY;

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error(
    "❌ Missing SUPABASE_URL or SUPABASE_SECRET_KEY in environment variables."
  );
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY
);

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.use(
  cors({
    origin: "*",
  })
);

app.use(
  express.json({
    limit: "20mb",
  })
);

// --------------------------------------------------
// Multer
// --------------------------------------------------

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
});

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
// Image Upload API
// --------------------------------------------------

app.post(
  "/api/upload",
  upload.single("image"),
  async (req, res) => {
    try {
      // --------------------------------------------------
      // Check uploaded file
      // --------------------------------------------------

      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: "No image file received.",
        });
      }

      console.log(
        "================================="
      );

      console.log(
        "📤 Uploading image to Supabase..."
      );

      console.log(
        "Filename:",
        req.file.originalname
      );

      console.log(
        "Mimetype:",
        req.file.mimetype
      );

      console.log(
        "Size:",
        req.file.size
      );

      // --------------------------------------------------
      // Generate unique filename
      // --------------------------------------------------

      const extension =
        req.file.mimetype === "image/png"
          ? "png"
          : req.file.mimetype === "image/webp"
          ? "webp"
          : "jpg";

      const fileName = `${Date.now()}-${Math.floor(
        Math.random() * 1000000000
      )}.${extension}`;

      console.log(
        "Supabase filename:",
        fileName
      );

      // --------------------------------------------------
      // Upload to Supabase Storage
      // --------------------------------------------------

      const {
        data,
        error,
      } =
        await supabase.storage
          .from("student-photos")
          .upload(
            fileName,
            req.file.buffer,
            {
              contentType:
                req.file.mimetype,
              upsert: false,
            }
          );

      if (error) {
        console.error(
          "❌ Supabase upload error:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Failed to upload image to Supabase.",
          error: error.message,
        });
      }

      console.log(
        "✅ Supabase upload successful:",
        data
      );

      // --------------------------------------------------
      // Create Public URL
      // --------------------------------------------------

      const {
        data: publicUrlData,
      } =
        supabase.storage
          .from("student-photos")
          .getPublicUrl(fileName);

      const publicUrl =
        publicUrlData?.publicUrl || "";

      if (!publicUrl) {
        console.error(
          "❌ Failed to create Supabase public URL."
        );

        return res.status(500).json({
          success: false,
          message:
            "Image uploaded but public URL could not be created.",
        });
      }

      console.log(
        "✅ Public image URL:",
        publicUrl
      );

      console.log(
        "================================="
      );

      // --------------------------------------------------
      // Response
      // --------------------------------------------------

      return res.status(200).json({
        success: true,
        message:
          "Image uploaded successfully.",
        url: publicUrl,
        fileName,
      });
    } catch (error) {
      console.error(
        "❌ Upload image error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          error.message ||
          "Image upload failed.",
      });
    }
  }
);

// --------------------------------------------------
// Image Delete API
// --------------------------------------------------

app.post(
  "/api/delete-images",
  async (req, res) => {
    try {
      const {
        urls = [],
      } = req.body;

      if (!Array.isArray(urls)) {
        return res.status(400).json({
          success: false,
          message: "urls must be an array.",
        });
      }

      // --------------------------------------------------
      // Remove empty / invalid values
      // --------------------------------------------------

      const validUrls = urls.filter(
        (url) =>
          typeof url === "string" &&
          url.trim() !== ""
      );

      if (validUrls.length === 0) {
        return res.json({
          success: true,
          message: "No images to delete.",
          deleted: [],
        });
      }

      // --------------------------------------------------
      // Convert Supabase public URLs
      // → storage filenames
      // --------------------------------------------------

      const fileNames = validUrls
        .map((url) => {
          try {
            const parsedUrl =
              new URL(url);

            const marker =
              "/storage/v1/object/public/student-photos/";

            const index =
              parsedUrl.pathname.indexOf(
                marker
              );

            if (index === -1) {
              return null;
            }

            return decodeURIComponent(
              parsedUrl.pathname.slice(
                index + marker.length
              )
            );
          } catch (error) {
            console.error(
              "Invalid image URL:",
              url
            );

            return null;
          }
        })
        .filter(Boolean);

      if (fileNames.length === 0) {
        return res.status(400).json({
          success: false,
          message:
            "No valid Supabase student photo URLs found.",
        });
      }

      console.log(
        "🗑️ Deleting Supabase files:",
        fileNames
      );

      // --------------------------------------------------
      // Delete from Supabase Storage
      // --------------------------------------------------

      const {
        data,
        error,
      } =
        await supabase.storage
          .from("student-photos")
          .remove(fileNames);

      if (error) {
        console.error(
          "❌ Supabase image delete error:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Failed to delete image(s) from Supabase.",
          error: error.message,
        });
      }

      // --------------------------------------------------
      // Response
      // --------------------------------------------------

      return res.json({
        success: true,
        message:
          "Image(s) deleted successfully.",
        deleted: data || [],
      });
    } catch (error) {
      console.error(
        "❌ Delete images error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          error.message ||
          "Image deletion failed.",
      });
    }
  }
);

// --------------------------------------------------
// Image Proxy API
// --------------------------------------------------

app.get(
  "/api/student-photo",
  async (req, res) => {
    try {
      const {
        url = "",
      } = req.query;

      if (
        typeof url !== "string" ||
        url.trim() === ""
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Image URL is required.",
        });
      }

      // --------------------------------------------------
      // Validate Supabase public URL
      // --------------------------------------------------

      const parsedUrl =
        new URL(url);

      const marker =
        "/storage/v1/object/public/student-photos/";

      const index =
        parsedUrl.pathname.indexOf(
          marker
        );

      if (index === -1) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid student photo URL.",
        });
      }

      // --------------------------------------------------
      // Get storage filename
      // --------------------------------------------------

      const fileName =
        decodeURIComponent(
          parsedUrl.pathname.slice(
            index + marker.length
          )
        );

      if (!fileName) {
        return res.status(400).json({
          success: false,
          message:
            "Student photo filename is missing.",
        });
      }

      console.log(
        "🖼️ Proxy loading image:",
        fileName
      );

      // --------------------------------------------------
      // Download image from Supabase Storage
      // --------------------------------------------------

      const {
        data,
        error,
      } =
        await supabase.storage
          .from("student-photos")
          .download(fileName);

      if (error) {
        console.error(
          "❌ Supabase image download error:",
          error
        );

        return res.status(404).json({
          success: false,
          message:
            "Student photo not found.",
          error:
            error.message,
        });
      }

      if (!data) {
        return res.status(404).json({
          success: false,
          message:
            "Student photo is empty.",
        });
      }

      // --------------------------------------------------
      // Convert Blob → Buffer
      // --------------------------------------------------

      const arrayBuffer =
        await data.arrayBuffer();

      const buffer =
        Buffer.from(arrayBuffer);

      // --------------------------------------------------
      // Detect image type
      // --------------------------------------------------

      const contentType =
        data.type ||
        "image/jpeg";

      // --------------------------------------------------
      // CORS
      // --------------------------------------------------

      res.setHeader(
        "Access-Control-Allow-Origin",
        "*"
      );

      // --------------------------------------------------
      // Response Headers
      // --------------------------------------------------

      res.setHeader(
        "Content-Type",
        contentType
      );

      res.setHeader(
        "Content-Length",
        buffer.length
      );

      res.setHeader(
        "Cache-Control",
        "public, max-age=3600"
      );

      // --------------------------------------------------
      // Send image to browser
      // --------------------------------------------------

      return res.send(buffer);
    } catch (error) {
      console.error(
        "❌ Image proxy error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          error.message ||
          "Failed to load student photo.",
      });
    }
  }
);
// --------------------------------------------------
// JOB STUDENT IMAGE UPLOAD API
// Separate storage from Attendance Student photos
// --------------------------------------------------

app.post(
  "/api/job-student/upload",
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: "No image file received.",
        });
      }

      console.log(
        "================================="
      );

      console.log(
        "📤 Uploading JOB STUDENT image..."
      );

      console.log(
        "Filename:",
        req.file.originalname
      );

      console.log(
        "Mimetype:",
        req.file.mimetype
      );

      console.log(
        "Size:",
        req.file.size
      );

      const extension =
        req.file.mimetype === "image/png"
          ? "png"
          : req.file.mimetype === "image/webp"
          ? "webp"
          : "jpg";

      const fileName = `${Date.now()}-${Math.floor(
        Math.random() * 1000000000
      )}.${extension}`;

      console.log(
        "Job Student Supabase filename:",
        fileName
      );

      const {
        data,
        error,
      } =
        await supabase.storage
          .from("job-student-photos")
          .upload(
            fileName,
            req.file.buffer,
            {
              contentType:
                req.file.mimetype,
              upsert: false,
            }
          );

      if (error) {
        console.error(
          "❌ Job Student Supabase upload error:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Failed to upload Job Student image to Supabase.",
          error: error.message,
        });
      }

      console.log(
        "✅ Job Student upload successful:",
        data
      );

      const {
        data: publicUrlData,
      } =
        supabase.storage
          .from("job-student-photos")
          .getPublicUrl(fileName);

      const publicUrl =
        publicUrlData?.publicUrl || "";

      if (!publicUrl) {
        console.error(
          "❌ Failed to create Job Student public URL."
        );

        return res.status(500).json({
          success: false,
          message:
            "Image uploaded but public URL could not be created.",
        });
      }

      console.log(
        "✅ Job Student public image URL:",
        publicUrl
      );

      console.log(
        "================================="
      );

      return res.status(200).json({
        success: true,
        message:
          "Job Student image uploaded successfully.",
        url: publicUrl,
        fileName,
      });
    } catch (error) {
      console.error(
        "❌ Job Student upload error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          error.message ||
          "Job Student image upload failed.",
      });
    }
  }
);

// --------------------------------------------------
// JOB STUDENT IMAGE DELETE API
// Separate from Attendance Student delete API
// --------------------------------------------------

app.post(
  "/api/job-student/delete-images",
  async (req, res) => {
    try {
      const {
        urls = [],
      } = req.body;

      if (!Array.isArray(urls)) {
        return res.status(400).json({
          success: false,
          message: "urls must be an array.",
        });
      }

      const validUrls = [
        ...new Set(
          urls.filter(
            (url) =>
              typeof url === "string" &&
              url.trim() !== ""
          )
        ),
      ];

      if (validUrls.length === 0) {
        return res.json({
          success: true,
          message: "No images to delete.",
          deleted: [],
        });
      }

      const fileNames = validUrls
        .map((url) => {
          try {
            const parsedUrl =
              new URL(url);

            const marker =
              "/storage/v1/object/public/job-student-photos/";

            const index =
              parsedUrl.pathname.indexOf(
                marker
              );

            if (index === -1) {
              return null;
            }

            return decodeURIComponent(
              parsedUrl.pathname.slice(
                index + marker.length
              )
            );
          } catch (error) {
            console.error(
              "Invalid Job Student image URL:",
              url
            );

            return null;
          }
        })
        .filter(Boolean);

      if (fileNames.length === 0) {
        return res.status(400).json({
          success: false,
          message:
            "No valid Job Student photo URLs found.",
        });
      }

      console.log(
        "🗑️ Deleting Job Student files:",
        fileNames
      );

      const {
        data,
        error,
      } =
        await supabase.storage
          .from("job-student-photos")
          .remove(fileNames);

      if (error) {
        console.error(
          "❌ Job Student image delete error:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Failed to delete Job Student image(s) from Supabase.",
          error: error.message,
        });
      }

      return res.json({
        success: true,
        message:
          "Job Student image(s) deleted successfully.",
        deleted: data || [],
      });
    } catch (error) {
      console.error(
        "❌ Job Student delete images error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          error.message ||
          "Job Student image deletion failed.",
      });
    }
  }
);

// --------------------------------------------------
// JOB STUDENT IMAGE PROXY API
// Separate from Attendance Student photo proxy
// --------------------------------------------------

app.get(
  "/api/job-student-photo",
  async (req, res) => {
    try {
      const {
        url = "",
      } = req.query;

      if (
        typeof url !== "string" ||
        url.trim() === ""
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Job Student image URL is required.",
        });
      }

      const parsedUrl =
        new URL(url);

      const marker =
        "/storage/v1/object/public/job-student-photos/";

      const index =
        parsedUrl.pathname.indexOf(
          marker
        );

      if (index === -1) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid Job Student photo URL.",
        });
      }

      const fileName =
        decodeURIComponent(
          parsedUrl.pathname.slice(
            index + marker.length
          )
        );

      if (!fileName) {
        return res.status(400).json({
          success: false,
          message:
            "Job Student photo filename is missing.",
        });
      }

      console.log(
        "🖼️ Loading Job Student image:",
        fileName
      );

      const {
        data,
        error,
      } =
        await supabase.storage
          .from("job-student-photos")
          .download(fileName);

      if (error) {
        console.error(
          "❌ Job Student image download error:",
          error
        );

        return res.status(404).json({
          success: false,
          message:
            "Job Student photo not found.",
          error:
            error.message,
        });
      }

      if (!data) {
        return res.status(404).json({
          success: false,
          message:
            "Job Student photo is empty.",
        });
      }

      const arrayBuffer =
        await data.arrayBuffer();

      const buffer =
        Buffer.from(arrayBuffer);

      const contentType =
        data.type ||
        "image/jpeg";

      res.setHeader(
        "Access-Control-Allow-Origin",
        "*"
      );

      res.setHeader(
        "Content-Type",
        contentType
      );

      res.setHeader(
        "Content-Length",
        buffer.length
      );

      res.setHeader(
        "Cache-Control",
        "public, max-age=3600"
      );

      return res.send(buffer);
    } catch (error) {
      console.error(
        "❌ Job Student image proxy error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          error.message ||
          "Failed to load Job Student photo.",
      });
    }
  }
);
// --------------------------------------------------
// Start Server
// --------------------------------------------------

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `🚀 Backend server running on port ${PORT}`
    );
  }
);