<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <style>
        /* General Body Styling */
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
            background: linear-gradient(to right, #000000, #ffffff);  /* Cool blue gradient */
        }

        /* Login Container Styling */
        .login-container {
            background-color: #fff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 400px; /* Maximum width for larger screens */
            text-align: center;
        }

        /* Heading Styling */
        .login-container h1 {
            margin-bottom: 20px;
            color: #333;
            font-size: 24px;
        }

        /* Form Group Styling */
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }

        /* Label Styling */
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-size: 14px;
        }

        /* Input Styling */
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-sizing: border-box;
            font-size: 16px;
        }

        /* Button Styling */
        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 8px;
            background-color: #007bff;
            color: #fff;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        /* Button Hover Effect */
        button:hover {
            background-color: #0056b3;
        }

        /* New User Link Styling */
        .new-user {
            margin-top: 20px;
            font-size: 14px;
        }

        .new-user a {
            color: #007bff;
            text-decoration: none;
        }

        .new-user a:hover {
            text-decoration: underline;
        }

        /* Responsive Design */
        @media (max-width: 480px) {
            .login-container {
                padding: 20px;
            }
            
            .form-group input {
                padding: 10px;
                font-size: 14px;
            }
            
            button {
                padding: 10px;
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        <form action="webapi/myresource/login" method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required placeholder="Enter your username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required placeholder="Enter your password">
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="new-user">
            <p>New user? <a href="/cybersolve/Register.html">Create an account</a></p>
            
        <a href="/cybersolve/forgotpassword.html">Forgot Password?</a>
        </div>
        
    </div>
</body>
</html>
