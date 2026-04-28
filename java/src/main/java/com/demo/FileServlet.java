package com.demo;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// A01:Broken Access Control — Path Traversal
public class FileServlet extends HttpServlet {

    private static final String BASE_DIR = "/var/app/files/";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String filename = request.getParameter("filename");

        // Validate and sanitize the filename to prevent path traversal
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Filename parameter is required");
            return;
        }

        // Normalize the path and validate it stays within BASE_DIR
        File baseDir = new File(BASE_DIR).getCanonicalFile();
        File file = new File(baseDir, filename).getCanonicalFile();

        // Ensure the resolved path is within the base directory
        if (!file.getCanonicalPath().startsWith(baseDir.getCanonicalPath() + File.separator)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        // Check if file exists and is a regular file
        if (!file.exists() || !file.isFile()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            return;
        }

        response.setContentType("application/octet-stream");
        try (FileInputStream fis = new FileInputStream(file);
             OutputStream os = response.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
        }
    }
}
