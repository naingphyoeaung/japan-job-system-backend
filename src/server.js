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

      // Remove empty / invalid values
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
      // Convert Supabase public URLs → storage filenames
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
          "Supabase image delete error:",
          error
        );

        return res.status(500).json({

          success: false,

          message:
            "Failed to delete image(s) from Supabase.",

          error:
            error.message,

        });

      }

      // --------------------------------------------------
      // Response
      // --------------------------------------------------

      return res.json({

        success: true,

        message:
          "Image(s) deleted successfully.",

        deleted:
          data || [],

      });

    } catch (error) {

      console.error(
        "Delete images error:",
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
          message: "Image URL is required.",
        });

      }

      // --------------------------------------------------
      // Convert Supabase public URL → storage filename
      // --------------------------------------------------

      const parsedUrl = new URL(url);

      const marker =
        "/storage/v1/object/public/student-photos/";

      const index =
        parsedUrl.pathname.indexOf(marker);

      if (index === -1) {

        return res.status(400).json({
          success: false,
          message:
            "Invalid student photo URL.",
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
        error
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
      // Response headers
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