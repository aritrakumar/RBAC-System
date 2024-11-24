# RBAC System

This project is a basic implementation of an **Authentication**, **Authorization**, and **Role-Based Access Control (RBAC)** system using Node.js and SQLite. Users can register, log in, and roles can be assigned to control access to different resources.

## Features

- **User Registration**: Users can register with a unique username and password.
- **User Login**: Users can log in to receive a JWT token for authentication.
- **Role Assignment**: Roles such as Admin, User, and Moderator can be assigned to users.
- **Role-Based Access Control**: Certain routes are protected and can only be accessed by users with the appropriate role.

## Technologies Used

- **Node.js**: Server-side JavaScript runtime.
- **Express**: Web framework for Node.js.
- **SQLite**: Relational database for storing user, role, and user-role data.
- **bcryptjs**: Library for hashing passwords.
- **jsonwebtoken**: Library for creating and verifying JSON Web Tokens (JWT).

## Prerequisites

- **Node.js** installed on your machine.
- **npm** (Node Package Manager) installed.

## Setup Instructions

1. **Clone the Repository**
   ```sh
   git clone <repository-url>
   cd rbac_system
   ```

2. **Install Dependencies**
   ```sh
   npm install
   ```

3. **Run the Application**
   ```sh
   node app.js
   ```

4. **Database Setup**
   The SQLite database (`rbac_system.db`) is created automatically when the server runs for the first time.

## Endpoints

### User Registration
- **URL**: `/register`
- **Method**: `POST`
- **Payload**:
  ```json
  {
    "username": "exampleUser",
    "password": "examplePassword"
  }
  ```
- **Response**: User registered successfully or error message.

### User Login
- **URL**: `/login`
- **Method**: `POST`
- **Payload**:
  ```json
  {
    "username": "exampleUser",
    "password": "examplePassword"
  }
  ```
- **Response**: JWT token or error message.

### Assign Role to User
- **URL**: `/assign_role`
- **Method**: `POST`
- **Headers**: `x-access-token` (JWT token received during login)
- **Payload**:
  ```json
  {
    "username": "exampleUser",
    "role": "Admin"
  }
  ```
- **Response**: Role assigned successfully or error message.

### Admin Protected Route
- **URL**: `/admin`
- **Method**: `GET`
- **Headers**: `x-access-token` (JWT token received during login)
- **Response**: Access message or error message if unauthorized.

## Testing the Endpoints

You can use tools like **Postman** or **cURL** to test the endpoints.

1. **Register a User**: Send a `POST` request to `/register` with a JSON payload containing `username` and `password`.
2. **Log in**: Send a `POST` request to `/login` with the same credentials. You will receive a JWT token.
3. **Assign Role**: Send a `POST` request to `/assign_role` with the JWT token in headers and the role assignment payload.
4. **Access Admin Route**: Send a `GET` request to `/admin` with the JWT token in headers.

## Additional Notes

- Ensure that the `x-access-token` header is included in requests to protected routes.
- Default roles (`Admin`, `User`, `Moderator`) are created when the server starts for the first time.

## License

This project is open source and available under the [MIT License](LICENSE).

