import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

// --------------------------------------------------
// Supabase
// --------------------------------------------------

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

// --------------------------------------------------
// ES Module __dirname
// --------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --------------------------------------------------
// Temporary Upload Folder
// --------------------------------------------------

const uploadDir = path.join(
  __dirname,
  "../uploads"
);

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, {
    recursive: true,
  });
}

// --------------------------------------------------
// Multer Storage
// --------------------------------------------------

const storage = multer.diskStorage({

  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },

  filename: (req, file, cb) => {

    const extension =
      path.extname(file.originalname);

    const filename =
      `${Date.now()}-${Math.round(
        Math.random() * 1e9
      )}${extension}`;

    cb(null, filename);
  },

});

// --------------------------------------------------
// Multer Upload
// --------------------------------------------------

const upload = multer({

  storage,

  limits: {
    fileSize: 20 * 1024 * 1024,
  },

  fileFilter: (req, file, cb) => {

    if (
      file.mimetype.startsWith("image/")
    ) {

      cb(null, true);

    } else {

      cb(
        new Error(
          "Only image files are allowed."
        )
      );

    }

  },

});

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.use(cors());

app.use(express.json());

// Temporary local uploads
app.use(
  "/uploads",
  express.static(uploadDir)
);

// Test page
app.use(
  "/test",
  express.static(
    path.join(__dirname, "../")
  )
);

// --------------------------------------------------
// Health Check
// --------------------------------------------------

app.get(
  "/api/health",
  (req, res) => {

    res.json({

      success: true,

      message:
        "Japan Job System Backend is running!",

    });

  }
);

// --------------------------------------------------
// Image Upload API
// --------------------------------------------------

app.post(
  "/api/upload",
  upload.single("image"),
  async (req, res) => {

    try {

      if (!req.file) {

        return res.status(400).json({

          success: false,

          message:
            "No image uploaded.",

        });

      }

      // --------------------------------------------------
      // Read uploaded image
      // --------------------------------------------------

      const fileBuffer =
        fs.readFileSync(
          req.file.path
        );

      // --------------------------------------------------
      // Upload image to Supabase Storage
      // --------------------------------------------------

      const {
        error: uploadError,
      } =
        await supabase.storage
          .from("student-photos")
          .upload(
            req.file.filename,
            fileBuffer,
            {
              contentType:
                req.file.mimetype,

              upsert: true,
            }
          );

      // --------------------------------------------------
      // Supabase upload error
      // --------------------------------------------------

      if (uploadError) {

        console.error(
          "Supabase upload error:",
          uploadError
        );

        return res.status(500).json({

          success: false,

          message:
            "Failed to upload image to Supabase.",

        });

      }

      // --------------------------------------------------
      // Get public URL
      // --------------------------------------------------

      const {
        data: publicUrlData,
      } =
        supabase.storage
          .from("student-photos")
          .getPublicUrl(
            req.file.filename
          );

      const imageUrl =
        publicUrlData.publicUrl;

      // --------------------------------------------------
      // Delete temporary local file
      // --------------------------------------------------

      try {

        fs.unlinkSync(
          req.file.path
        );

      } catch (deleteError) {

        console.error(
          "Temporary file delete error:",
          deleteError
        );

      }

      // --------------------------------------------------
      // Response
      // --------------------------------------------------

      res.json({

        success: true,

        message:
          "Image uploaded successfully.",

        filename:
          req.file.filename,

        originalName:
          req.file.originalname,

        size:
          req.file.size,

        url:
          imageUrl,

      });

    } catch (error) {

      console.error(
        "Upload error:",
        error
      );

      res.status(500).json({

        success: false,

        message:
          error.message ||
          "Image upload failed.",

      });

    }

  }
);

// --------------------------------------------------
// Error Handler
// --------------------------------------------------

app.use(
  (error, req, res, next) => {

    console.error(error);

    if (
      error instanceof multer.MulterError
    ) {

      if (
        error.code ===
        "LIMIT_FILE_SIZE"
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Image size must be 20MB or less.",

        });

      }

    }

    res.status(500).json({

      success: false,

      message:
        error.message ||
        "Server error.",

    });

  }
);

// --------------------------------------------------
// Start Server
// --------------------------------------------------

app.listen(
  PORT,
  () => {

    console.log(
      `Backend server running on http://localhost:${PORT}`
    );

  }
);