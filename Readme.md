# Two-Backend System with Secure API Communication

## Overview
This project consists of two separate backend services:
- **Backend 1 (Sensitive Data Service)**: Handles sensitive data (username, email, password) and aggregates data from Backend 2.
- **Backend 2 (Non-Sensitive Data Service)**: Handles non-sensitive profile data (bio, interests).

## Prerequisites
- Node.js (v14.x or higher)
- MongoDB Atlas or local MongoDB server
- `nodemon` (install globally with `npm install -g nodemon`)

## Setup Instructions

### 1. Clone the Repository
git clone <repository-url>
cd <project-directory>

### 2. Install Dependencies
##### For Backend 1: 
```
cd back1
npm install
```
##### For Backend 2: 
```
cd back2
npm install
```

### 3. Configure Environment Variables
##### Backend 1 .env:
```
MONGO_SERVER=mongodb+srv://<username>:<password>@cluster0.mongodb.net/back1
PORT=3001
JWT_SECRET_KEY=SECRET_KEY
BACKEND_2_URL=http://localhost:3002

```
##### Backend 2 .env:
```
MONGO_SERVER=mongodb+srv://<username>:<password>@cluster0.mongodb.net/back2
PORT=3002
JWT_SECRET_KEY=SECRET_KEY

```
### 4. Start Both Backends
```
nodemon server.js [for both]
```
### 5. API Endpoints
#####  POST /user (Backend 1)
```
POST http://localhost:3001/user

{
  "username": "johndoe",
  "email": "johndoe@example.com",
  "password": "securepassword123",
  "bio": "Software Developer",
  "interests": ["coding", "gaming"]
}
```
#####  GET /user/:id (Backend 1)
```
GET http://localhost:3001/user/<user_id>
```
#####  GET /profile/:userId (Backend 2)
```
GET http://localhost:3002/profile/<user_id>
```
```
post to "localhost:3001/user/"
```
![1 send_data](https://github.com/user-attachments/assets/829f1961-b069-4330-9c9f-679f296e375f)
```
get user data by Id : localhost:3001/user/<id>
```
![2 get_user_data_by_id](https://github.com/user-attachments/assets/01c44212-05a8-4aec-a5ec-0c801f54e6e5)
```
get profile data for specific user : localhost:3002/profile/<id>
```
![3 get_profile_data](https://github.com/user-attachments/assets/b78bab6d-0c2c-47d1-8211-19af03f83915)
```
user database for Sensitive Data
```
![4 databse_user](https://github.com/user-attachments/assets/9e569fc9-5de3-4b03-8478-755d2451e710)
```
profile database Non-Sensitive Data
```
![5 databse_profile](https://github.com/user-attachments/assets/3d743754-fdd3-43de-9cac-97435d4c1ea4)
