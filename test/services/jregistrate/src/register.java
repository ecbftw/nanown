package jregistrate;

import java.lang.System;
import java.io.*;
import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.sql.*;
import org.sqlite.JDBC;


/* Copyright (C) 2015 Blindspot Security LLC. All rights reserved. 
 * Author: Timothy D. Morgan
 */
public final class register extends BaseServlet 
{
    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
      throws IOException, ServletException 
    {
        response.setContentType("text/html");

        PrintWriter writer = response.getWriter();
        writer.println("<html>");
        writer.println("<head>");
        writer.println("<title>Register for an Account</title>");
        writer.println("</head>");
        writer.println("<body bgcolor='#EEFFEE'>");
        String error = (String)request.getAttribute("error");
        if (error != null)
        {
            writer.println("<span style='color: red;'>ERROR:"+error+"</span>");
        }
        writer.println("<!-- Hint: sample valid: 0012-8846,9475 -->");
        
        String member_id = request.getParameter("member_id");
        member_id = (member_id == null) ? "" : member_id;
        String last_four = request.getParameter("last_four");
        last_four = (last_four == null) ? "" : last_four;
        //String zip_code = request.getParameter("zip_code");
        //zip_code = (zip_code == null) ? "" : zip_code;
        String username = request.getParameter("username");
        username = (username == null) ? "" : username;
        String password = request.getParameter("password");
        password = (password == null || !password.equals(request.getParameter("conf_pwd"))) ? "" : password;
        
        
        writer.println("<form action='register' method='POST'>");
        writer.println("<table border=\"0\" cellpadding=\"10\">");

        writer.println("<tr><td colspan='3'>");
        writer.println("<h1>Boobie Veterinary Insurance Company, Inc, LLC</h1>");
        writer.println("</td></tr>");
        
        writer.println("<tr><td colspan='2'><h2>Register for Your Online Account</h2></td>");
        writer.println("<td rowspan='10'><img src='images/blue-footed-boobie.jpg' height='300' border='1' /></td>");
        writer.println("</tr>");

        writer.println("<tr><td>Membership ID<br/>(Format: ####-####):</td><td><input type='text' name='member_id' value='"+htmlEncode(member_id)+"' /></td></tr>");
        writer.println("<tr><td>Last 4 of SSN:</td><td><input type='text' name='last_four' value='"+htmlEncode(last_four)+"' /></td></tr>");
        //writer.println("<tr><td>Zip Code:     </td><td><input type='text' name='zip_code' value='"+htmlEncode(zip_code)+"' /></td></tr>");
        writer.println("<tr></tr>");
        writer.println("<tr><td>Username:</td><td><input type='text' name='username' value='"+htmlEncode(username)+"' /></td></tr>");
        writer.println("<tr><td>Password:</td><td><input type='text' name='password' value='' /></td></tr>");
        writer.println("<tr><td>Confirm Password:</td><td><input type='text' name='conf_pwd' value='' /></td></tr>");
        writer.println("<tr><td><input type='submit' value='submit'></td></tr>");
        writer.println("</table>");
        writer.println("</form>");
        writer.println("</body>");
        writer.println("</html>");
    }


    public void doPost(HttpServletRequest request,
                       HttpServletResponse response)
        throws IOException, ServletException
    {
        request.setAttribute("error", null);
        try
        {
            String member_id = request.getParameter("member_id");
            member_id = (member_id == null) ? "" : member_id;
            String last_four = request.getParameter("last_four");
            last_four = (last_four == null) ? "" : last_four;
            //String zip_code = request.getParameter("zip_code");
            //zip_code = (zip_code == null) ? "" : zip_code;
            String username = request.getParameter("username");
            username = (username == null) ? "" : username;
            String password = request.getParameter("password");
            password = (password == null || !password.equals(request.getParameter("conf_pwd"))) ? "" : password;
            
            
            Connection db = openDB();
            PreparedStatement ps = db.prepareStatement("SELECT * FROM members WHERE member_id=?");
            ps.setString(1, member_id);
            ResultSet rs = ps.executeQuery();
            long start = System.nanoTime();
            PrintWriter writer = response.getWriter();
            if (rs.next())
            {
                if (last_four.equals(decryptLastFour(rs.getString("enc_last_four"))))
                {
                    if (!"".equals(password))
                    {
                        // member_id already registered?
                        // username already registered?
                        response.setContentType("text/html");
                        writer.println("<html><body>Registration Successful!</body></html>");
                        return;
                    }
                    else
                        request.setAttribute("error", "Bad password or passwords don't match");
                }
            }
            response.addHeader("X-Response-Time", String.format("%fms", (System.nanoTime()-start)/1000000.0));
            if (request.getAttribute("error") == null)
                request.setAttribute("error", "Invalid personal information specified.  Try again.");
        }
        catch (Exception e)
        {
            request.setAttribute("error", "Unknown error occurred.  See logs.");
            e.printStackTrace();
        }
        
        doGet(request, response);
    }

}
