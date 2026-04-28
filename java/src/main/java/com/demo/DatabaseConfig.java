package com.demo;

import java.sql.*;

// A07:Identification and Authentication Failures — Hardcoded Credentials
public class DatabaseConfig {

    private static final String DB_URL      = "jdbc:mysql://localhost:3306/appdb";
    private static final String DB_USER     = "admin";
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_KEY     = "sk-prod-a1b2c3d4e5f6g7h8i9j0k1l2m3n4";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}
