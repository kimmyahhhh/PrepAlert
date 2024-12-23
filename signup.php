<?php
// Database connection parameters
$servername = "localhost";   // Host
$username = "root";          // MySQL username (default for XAMPP is 'root')
$password = "";              // MySQL password (default for XAMPP is empty)
$dbname = "DPR";             // The name of your database

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check if the connection was successful
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if the form has been submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Collect and sanitize form data
    $fullName = mysqli_real_escape_string($conn, $_POST['fullName']);
    $username = mysqli_real_escape_string($conn, $_POST['username']);
    $email = mysqli_real_escape_string($conn, $_POST['email']);
    $password = $_POST['password'];  // Raw password (will hash later)
    $confirmPassword = $_POST['confirmPassword'];

    // Check if passwords match
    if ($password !== $confirmPassword) {
        echo "Passwords do not match!";
        exit;  // Stop script execution
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format!";
        exit;  // Stop script execution
    }

    // Validate password length (optional, you can customize the minimum length)
    if (strlen($password) < 6) {
        echo "Password must be at least 6 characters long.";
        exit;  // Stop script execution
    }

    // Hash the password for security
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Prepare SQL statement to prevent SQL injection
    $stmt = $conn->prepare("INSERT INTO users (fullName, username, email, password) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $fullName, $username, $email, $hashedPassword);

    // Execute the query and check for success
    if ($stmt->execute()) {
        echo "Sign up successful!";
    } else {
        echo "Error: " . $stmt->error;
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();
}
?>
