package com.demo;

import java.sql.*;

// A03:Injection — SQL Injection
public class UserDao {

    private Connection connection;

    public UserDao(Connection connection) {
        this.connection = connection;
    }

    public ResultSet getUserByUsername(String username) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(query);
    }

    public void deleteUser(String userId) throws SQLException {
        String query = "DELETE FROM users WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        stmt.executeUpdate(query);
    }
}
