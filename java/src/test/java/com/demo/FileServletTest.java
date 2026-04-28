package com.demo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Test class for FileServlet to verify HSTS header implementation
 * and proper security headers in HTTP responses.
 */
@ExtendWith(MockitoExtension.class)
public class FileServletTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private ServletOutputStream outputStream;

    private FileServlet servlet;
    private File testFile;

    @BeforeEach
    public void setUp() throws IOException {
        servlet = new FileServlet();

        // Create a temporary test file in the expected directory structure
        // Note: In a real test environment, this would use a test-specific directory
        testFile = File.createTempFile("test", ".txt");
        testFile.deleteOnExit();

        try (FileOutputStream fos = new FileOutputStream(testFile)) {
            fos.write("Test file content".getBytes());
        }
    }

    /**
     * Test that HSTS header is present in the response.
     * This is the primary security test to verify the vulnerability fix.
     */
    @Test
    public void testHSTSHeaderIsPresent() throws ServletException, IOException {
        // Arrange
        when(request.getParameter("filename")).thenReturn(testFile.getName());
        when(response.getOutputStream()).thenReturn(outputStream);

        // Act
        servlet.doGet(request, response);

        // Assert - Verify HSTS header is set
        verify(response).setHeader(
            eq("Strict-Transport-Security"),
            eq("max-age=31536000; includeSubDomains")
        );
    }

    /**
     * Test that HSTS header has correct max-age value.
     * The max-age should be at least 1 year (31536000 seconds) per security best practices.
     */
    @Test
    public void testHSTSHeaderHasCorrectMaxAge() throws ServletException, IOException {
        // Arrange
        when(request.getParameter("filename")).thenReturn(testFile.getName());
        when(response.getOutputStream()).thenReturn(outputStream);

        // Act
        servlet.doGet(request, response);

        // Assert - Verify the header value includes proper max-age
        verify(response).setHeader(
            eq("Strict-Transport-Security"),
            argThat(headerValue ->
                headerValue != null &&
                headerValue.contains("max-age=31536000")
            )
        );
    }

    /**
     * Test that HSTS header includes includeSubDomains directive.
     * This ensures all subdomains are also protected by HSTS policy.
     */
    @Test
    public void testHSTSHeaderIncludesSubDomains() throws ServletException, IOException {
        // Arrange
        when(request.getParameter("filename")).thenReturn(testFile.getName());
        when(response.getOutputStream()).thenReturn(outputStream);

        // Act
        servlet.doGet(request, response);

        // Assert - Verify includeSubDomains directive is present
        verify(response).setHeader(
            eq("Strict-Transport-Security"),
            argThat(headerValue ->
                headerValue != null &&
                headerValue.contains("includeSubDomains")
            )
        );
    }

    /**
     * Test that HSTS header is set before content is written.
     * Headers must be set before the response body is written.
     */
    @Test
    public void testHSTSHeaderSetBeforeContentWritten() throws ServletException, IOException {
        // Arrange
        when(request.getParameter("filename")).thenReturn(testFile.getName());
        when(response.getOutputStream()).thenReturn(outputStream);

        // Act
        servlet.doGet(request, response);

        // Assert - Verify setHeader is called before getOutputStream
        // This ordering is critical for header to be effective
        var inOrder = inOrder(response, outputStream);
        inOrder.verify(response).setHeader(
            eq("Strict-Transport-Security"),
            anyString()
        );
        inOrder.verify(response).getOutputStream();
    }

    /**
     * Test that HSTS header is consistently set across multiple requests.
     * Security headers should be present on every response.
     */
    @Test
    public void testHSTSHeaderSetOnMultipleRequests() throws ServletException, IOException {
        // Arrange
        when(request.getParameter("filename")).thenReturn(testFile.getName());
        when(response.getOutputStream()).thenReturn(outputStream);

        // Act - Make multiple requests
        servlet.doGet(request, response);
        servlet.doGet(request, response);
        servlet.doGet(request, response);

        // Assert - Verify HSTS header is set on all requests
        verify(response, times(3)).setHeader(
            eq("Strict-Transport-Security"),
            eq("max-age=31536000; includeSubDomains")
        );
    }

    /**
     * Test that Content-Type header is still set correctly.
     * Verify that adding HSTS doesn't break existing functionality.
     */
    @Test
    public void testContentTypeStillSet() throws ServletException, IOException {
        // Arrange
        when(request.getParameter("filename")).thenReturn(testFile.getName());
        when(response.getOutputStream()).thenReturn(outputStream);

        // Act
        servlet.doGet(request, response);

        // Assert - Verify both security and functional headers are present
        verify(response).setContentType("application/octet-stream");
        verify(response).setHeader(
            eq("Strict-Transport-Security"),
            anyString()
        );
    }

    /**
     * Test that HSTS header value matches OWASP recommendations.
     * According to OWASP, HSTS should use max-age of at least 1 year
     * and include subdomains for comprehensive protection.
     */
    @Test
    public void testHSTSHeaderMatchesOWASPRecommendations() throws ServletException, IOException {
        // Arrange
        when(request.getParameter("filename")).thenReturn(testFile.getName());
        when(response.getOutputStream()).thenReturn(outputStream);

        // Act
        servlet.doGet(request, response);

        // Assert - Verify the complete OWASP-recommended header value
        verify(response).setHeader(
            eq("Strict-Transport-Security"),
            argThat(headerValue -> {
                if (headerValue == null) return false;

                // Check for minimum max-age of 1 year (31536000 seconds)
                boolean hasProperMaxAge = headerValue.matches(".*max-age=\\d+.*") &&
                    headerValue.contains("max-age=31536000");

                // Check for includeSubDomains directive
                boolean hasIncludeSubDomains = headerValue.contains("includeSubDomains");

                return hasProperMaxAge && hasIncludeSubDomains;
            })
        );
    }

    /**
     * Regression test: Ensure the servlet still functions correctly
     * after adding the HSTS header (positive functionality test).
     */
    @Test
    public void testServletStillFunctionsCorrectly() throws ServletException, IOException {
        // Arrange
        when(request.getParameter("filename")).thenReturn(testFile.getName());
        when(response.getOutputStream()).thenReturn(outputStream);

        // Act
        servlet.doGet(request, response);

        // Assert - Verify normal servlet operations still occur
        verify(request).getParameter("filename");
        verify(response).setContentType("application/octet-stream");
        verify(response).setHeader(eq("Strict-Transport-Security"), anyString());
        verify(response).getOutputStream();
        verify(outputStream, atLeastOnce()).write(any(byte[].class), anyInt(), anyInt());
    }
}
