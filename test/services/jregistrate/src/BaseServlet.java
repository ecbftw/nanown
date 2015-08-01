package jregistrate;

import java.io.*;
import java.util.*;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.sql.*;
import org.sqlite.JDBC;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.bind.DatatypeConverter;


/* Copyright (C) 2015 Blindspot Security LLC.  All rights reserved. 
 * Author: Timothy D. Morgan
 */
public class BaseServlet extends HttpServlet {
    protected Connection openDB()
    {
        Connection connection = null;
        try
        {
            Class.forName("org.sqlite.JDBC");
            // create a database connection
            connection = DriverManager.getConnection("jdbc:sqlite:webapps/jregistrate/WEB-INF/db/jregistrate.db");
            Statement statement = connection.createStatement();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return connection;
    }

    public String htmlEncode(String s)
    {
        return s.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll("\"", "&quot;").replaceAll("'", "&apos;");
    }
    
    public static byte[] hexStringToByteArray(String s) 
    {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                  + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    /*
    public static String decryptLastFour(String encrypted) throws Exception
    {
        byte[] cipher_text = DatatypeConverter.parseBase64Binary(encrypted);
        SecretKey key = new SecretKeySpec(hexStringToByteArray("5369787465656E2062797465206B6579"), "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        //Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plain_text = cipher.doFinal(cipher_text);
        
        return new String(plain_text, "utf-8");
    }
    */
    public static String decryptLastFour(String encrypted) throws Exception
    {
        int i, blocksize = 16;
        byte[] blob = DatatypeConverter.parseBase64Binary(encrypted);
        byte[] cipher_text = new byte[blob.length-blocksize];
        byte[] iv = new byte[blocksize];
        for(i=0; i < blocksize; i++)
            iv[i] = blob[i];
        for(i=blocksize; i < blob.length; i++)
            cipher_text[i-blocksize] = blob[i];
        
        SecretKey key = new SecretKeySpec(hexStringToByteArray("5369787465656E2062797465206B6579"), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        //Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plain_text = cipher.doFinal(cipher_text);
        
        return new String(plain_text, "utf-8");
    }
}
