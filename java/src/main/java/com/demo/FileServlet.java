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
        File file = new File(BASE_DIR + filename);

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
