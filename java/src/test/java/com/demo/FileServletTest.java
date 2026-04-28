package com.demo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test suite for FileServlet to validate path traversal vulnerability remediation.
 * Tests cover:
 * - Valid file access within the base directory
 * - Path traversal attack prevention using various techniques
 * - Edge cases and input validation
 * - Error handling
 */
public class FileServletTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private ServletOutputStream outputStream;

    private FileServlet servlet;

    @TempDir
    Path tempDir;

    private String originalBaseDir;

    @BeforeEach
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        servlet = new FileServlet();

        // Override BASE_DIR to use temp directory for testing
        Field baseDirField = FileServlet.class.getDeclaredField("BASE_DIR");
        baseDirField.setAccessible(true);
        originalBaseDir = (String) baseDirField.get(null);

        // Set BASE_DIR to temp directory with trailing separator
        String testBaseDir = tempDir.toFile().getCanonicalPath() + File.separator;
        baseDirField.set(null, testBaseDir);

        // Setup mock response output stream
        when(response.getOutputStream()).thenReturn(outputStream);
    }

    /**
     * Test valid file access - legitimate filename within base directory
     */
    @Test
    public void testValidFileAccess() throws ServletException, IOException {
        // Create a valid test file
        File testFile = new File(tempDir.toFile(), "test.txt");
        String content = "Test file content";
        try (FileOutputStream fos = new FileOutputStream(testFile)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
        }

        when(request.getParameter("filename")).thenReturn("test.txt");

        servlet.doGet(request, response);

        // Verify successful response
        verify(response).setContentType("application/octet-stream");
        verify(response, never()).sendError(anyInt(), anyString());
        verify(outputStream, atLeastOnce()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal attack using ../ sequences
     */
    @Test
    public void testPathTraversalWithParentDirectory() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("../etc/passwd");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal attack using multiple ../ sequences
     */
    @Test
    public void testPathTraversalWithMultipleParentDirectories() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("../../../../../../etc/passwd");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal attack using absolute path
     */
    @Test
    public void testPathTraversalWithAbsolutePath() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("/etc/passwd");

        servlet.doGet(request, response);

        // Verify access is denied (absolute path will not be within base directory)
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal using URL-encoded sequences
     */
    @Test
    public void testPathTraversalWithEncodedSequences() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("..%2F..%2Fetc%2Fpasswd");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal using backslash (Windows-style path)
     */
    @Test
    public void testPathTraversalWithBackslash() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("..\\..\\etc\\passwd");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal using mixed forward and back slashes
     */
    @Test
    public void testPathTraversalWithMixedSlashes() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("../..\\..\\etc/passwd");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal using dot-dot-slash in the middle of the path
     */
    @Test
    public void testPathTraversalInMiddleOfPath() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("subdir/../../etc/passwd");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test null filename parameter
     */
    @Test
    public void testNullFilename() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn(null);

        servlet.doGet(request, response);

        // Verify bad request error
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Filename parameter is required");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test empty filename parameter
     */
    @Test
    public void testEmptyFilename() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("");

        servlet.doGet(request, response);

        // Verify bad request error
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Filename parameter is required");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test accessing non-existent file
     */
    @Test
    public void testNonExistentFile() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("nonexistent.txt");

        servlet.doGet(request, response);

        // Verify not found error
        verify(response).sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test accessing a directory instead of a file
     */
    @Test
    public void testAccessDirectory() throws ServletException, IOException {
        // Create a subdirectory
        File subdir = new File(tempDir.toFile(), "subdir");
        subdir.mkdir();

        when(request.getParameter("filename")).thenReturn("subdir");

        servlet.doGet(request, response);

        // Verify not found error (directories should not be served)
        verify(response).sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test valid file in a subdirectory
     */
    @Test
    public void testValidFileInSubdirectory() throws ServletException, IOException {
        // Create a subdirectory and file
        File subdir = new File(tempDir.toFile(), "subdir");
        subdir.mkdir();
        File testFile = new File(subdir, "test.txt");
        String content = "Subdirectory test content";
        try (FileOutputStream fos = new FileOutputStream(testFile)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
        }

        when(request.getParameter("filename")).thenReturn("subdir" + File.separator + "test.txt");

        servlet.doGet(request, response);

        // Verify successful response
        verify(response).setContentType("application/octet-stream");
        verify(response, never()).sendError(anyInt(), anyString());
        verify(outputStream, atLeastOnce()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal that tries to escape via subdirectory
     */
    @Test
    public void testPathTraversalViaSubdirectory() throws ServletException, IOException {
        // Create a subdirectory
        File subdir = new File(tempDir.toFile(), "subdir");
        subdir.mkdir();

        when(request.getParameter("filename")).thenReturn("subdir/../../../etc/passwd");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal using Unicode encoding
     */
    @Test
    public void testPathTraversalWithUnicodeEncoding() throws ServletException, IOException {
        // Unicode encoding for ../ (\u002e\u002e\u002f)
        when(request.getParameter("filename")).thenReturn("\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal using double encoding
     */
    @Test
    public void testPathTraversalWithDoubleEncoding() throws ServletException, IOException {
        // Double encoded ../ (%252e%252e%252f)
        when(request.getParameter("filename")).thenReturn("%252e%252e%252f%252e%252e%252fetc%252fpasswd");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test file with special characters in valid filename
     */
    @Test
    public void testValidFileWithSpecialCharacters() throws ServletException, IOException {
        // Create a file with special characters in the name
        File testFile = new File(tempDir.toFile(), "test-file_123.txt");
        String content = "Special character test";
        try (FileOutputStream fos = new FileOutputStream(testFile)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
        }

        when(request.getParameter("filename")).thenReturn("test-file_123.txt");

        servlet.doGet(request, response);

        // Verify successful response
        verify(response).setContentType("application/octet-stream");
        verify(response, never()).sendError(anyInt(), anyString());
        verify(outputStream, atLeastOnce()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test path traversal using dot-dot-slash at the end
     */
    @Test
    public void testPathTraversalAtEnd() throws ServletException, IOException {
        when(request.getParameter("filename")).thenReturn("../../");

        servlet.doGet(request, response);

        // Verify access is denied
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        verify(outputStream, never()).write(any(byte[].class), anyInt(), anyInt());
    }

    /**
     * Test regression - ensure fix doesn't break legitimate file access
     */
    @Test
    public void testRegressionLegitimateAccess() throws ServletException, IOException {
        // Create multiple valid test files
        String[] filenames = {"file1.txt", "document.pdf", "image.jpg"};

        for (String filename : filenames) {
            File testFile = new File(tempDir.toFile(), filename);
            try (FileOutputStream fos = new FileOutputStream(testFile)) {
                fos.write(("Content of " + filename).getBytes(StandardCharsets.UTF_8));
            }

            when(request.getParameter("filename")).thenReturn(filename);

            servlet.doGet(request, response);

            // Verify successful response for each file
            verify(response, atLeastOnce()).setContentType("application/octet-stream");
        }
    }
}
