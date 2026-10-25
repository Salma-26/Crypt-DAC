package com.cryptdac.util;

import java.io.InputStream;
import java.sql.*;
import java.util.Properties;

public class DB {
    private static final Properties P = new Properties();
    static {
        try (InputStream in = DB.class.getResourceAsStream("/db.properties")) {
            P.load(in);
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }
    public static Connection get() throws SQLException {
        return DriverManager.getConnection(P.getProperty("url"), P.getProperty("user"), P.getProperty("password"));
    }
    public static String prop(String k) { return P.getProperty(k); }
}
