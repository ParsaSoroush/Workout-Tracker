# ⛓️ API Documentation of Workout Tracker Project

🔗 **Server Link:** http://localhost:8080/

---

## All Endpoints

### 📇 Sign Up
**Endpoint:** `POST /sign-up`
- ❌🔐 It not requires JWT token
- ✅🧾 It needs a body JSON

#### 📎 Example Request
```json
{
    "username": "John Doe",
    "password": "test1234"
}
```

#### 🖇️ Example Response
##### ✅ Success Response
```json
{
  "message": "User created successfully",
  "token": "BEARER TOKEN",
  "user": {
    "created_at": "2025-12-17T10:30:00Z",
    "id": 1,
    "username": "John Doe"
  }
}
```
⬆️ **It means the user has been created successfully and JWT token is generated** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "invalid form data"
}
```
⬆️ **It means the request is not correct and its invalid** ⬆️

```json
{
  "error": "failed to hash password"
}
```
⬆️ **It means there was an error hashing the password** ⬆️

```json
{
  "error": "Error 1062 (23000): Duplicate entry"
}
```
⬆️ **It means the username already exists** ⬆️

---

### ⛓️ Sign In
**Endpoint:** `POST /sign-in`
- ❌🔐 It not requires a JWT token
- ✅🧾 It needs a body JSON

#### 📎 Example Request
```json
{
  "username": "John Doe",
  "password": "test1234"
}
```

#### 🖇️ Example Response
##### ✅ Success Response
```json
{
  "message": "Login successful",
  "token": "BEARER TOKEN",
  "user": {
    "id": 1,
    "username": "John Doe"
  }
}
```
⬆️ **It means the user logged in and the Bearer Token has been generated** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "invalid input"
}
```
⬆️ **It means the request is not correct and its invalid** ⬆️

```json
{
  "error": "incorrect username or password"
}
```
⬆️ **It means the username or password is incorrect** ⬆️

---

### 🚪 Logout
**Endpoint:** `POST /logout`
- ❌🔐 It not requires a JWT token
- ❌🧾 It not requires a body JSON

#### 🖇️ Example Response
##### ✅ Success Response
```json
{
  "message": "Logout successful. Please delete token on client."
}
```
⬆️ **It means logout was successful, client should delete the token** ⬆️

---

### 🔒 Check JWT Token
**Endpoint:** `GET /check`
- ✅🔐 It requires a JWT Token
- ❌🧾 It not requires a body JSON

#### 🖇️ Example Response
##### ✅ Success Response
```json
{
  "message": "Token is valid",
  "remaining": "59m45.755473s",
  "user": {
    "id": 1,
    "username": "John Doe"
  }
}
```
⬆️ **It means token is valid and working correctly** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "no token provided"
}
```
⬆️ **It means the token is not added or you don't have any tokens** ⬆️

```json
{
  "error": "token is malformed: token contains an invalid number of segments"
}
```
⬆️ **It means JWT token is added but not in correct format** ⬆️

```json
{
  "error": "token is expired"
}
```
⬆️ **It means the JWT token has expired** ⬆️

---

### 🏋️ Get All Exercises
**Endpoint:** `GET /exercises`
- ❌🔐 It not requires a JWT token
- ❌🧾 It not requires a body JSON

#### 🖇️ Example Response
##### ✅ Success Response
```json
[
  {
    "id": 1,
    "name": "Bench Press",
    "description": "Barbell chest press",
    "category": "Strength",
    "muscle_group": "Chest",
    "created_at": "2025-12-17T10:00:00Z"
  },
  {
    "id": 2,
    "name": "Pull Ups",
    "description": "Bodyweight pulling exercise",
    "category": "Strength",
    "muscle_group": "Back",
    "created_at": "2025-12-17T10:00:00Z"
  },
  {
    "id": 3,
    "name": "Push Ups",
    "description": "Bodyweight push exercise",
    "category": "Strength",
    "muscle_group": "Chest",
    "created_at": "2025-12-17T10:00:00Z"
  }
]
```
⬆️ **It returns all available exercises ordered by name** ⬆️

##### 🛑 Error Response
```json
{
  "error": "failed to fetch exercises"
}
```
⬆️ **It means there was an error fetching exercises from database** ⬆️

---

### 📝 Add Workout
**Endpoint:** `POST /workouts`
- ✅🔐 It requires a JWT token
- ✅🧾 It needs a body JSON

#### 📎 Example Request
```json
{
  "title": "Morning Chest Workout",
  "description": "Chest and triceps workout",
  "comments": "Focus on form",
  "scheduled_for": "2025-12-18T08:00:00Z",
  "exercises": [
    {
      "exercise_id": 1,
      "sets": 4,
      "repetitions": 12,
      "weight": 80.5
    },
    {
      "exercise_id": 2,
      "sets": 3,
      "repetitions": 10,
      "weight": 0
    }
  ]
}
```

#### 🖇️ Example Response
##### ✅ Success Response
```json
{
  "id": 1,
  "title": "Morning Chest Workout",
  "description": "Chest and triceps workout",
  "status": "pending",
  "comments": "Focus on form",
  "scheduled_for": "2025-12-18T08:00:00Z",
  "created_at": "2025-12-17T10:30:00Z",
  "user_id": 1,
  "exercises": [
    {
      "id": 1,
      "workout_id": 1,
      "exercise_id": 1,
      "sets": 4,
      "repetitions": 12,
      "weight": 80.5,
      "exercise": {
        "id": 1,
        "name": "Bench Press",
        "description": "Barbell chest press",
        "category": "Strength",
        "muscle_group": "Chest",
        "created_at": "2025-12-17T10:00:00Z"
      },
      "created_at": "2025-12-17T10:30:00Z"
    }
  ]
}
```
⬆️ **It means workout has been created successfully with status "pending"** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "unauthorized"
}
```
⬆️ **It means JWT token is missing or invalid** ⬆️

```json
{
  "error": "invalid workout data: Key: 'title' Error:Field validation for 'title' failed on the 'required' tag"
}
```
⬆️ **It means required fields are missing** ⬆️

```json
{
  "error": "invalid datetime format (RFC3339)"
}
```
⬆️ **It means scheduled_for date format is incorrect** ⬆️

```json
{
  "error": "exercise id 99 not found"
}
```
⬆️ **It means one of the exercise IDs doesn't exist** ⬆️

---

### 📋 Get All Workouts
**Endpoint:** `GET /workouts`
- ✅🔐 It requires a JWT token
- ❌🧾 It not requires a body JSON

#### 🖇️ Example Response
##### ✅ Success Response
```json
[
  {
    "id": 1,
    "title": "Morning Chest Workout",
    "description": "Chest and triceps workout",
    "status": "pending",
    "comments": "Focus on form",
    "scheduled_for": "2025-12-18T08:00:00Z",
    "created_at": "2025-12-17T10:30:00Z",
    "user_id": 1,
    "exercises": [
      {
        "id": 1,
        "workout_id": 1,
        "exercise_id": 1,
        "sets": 4,
        "repetitions": 12,
        "weight": 80.5,
        "exercise": {
          "id": 1,
          "name": "Bench Press",
          "description": "Barbell chest press",
          "category": "Strength",
          "muscle_group": "Chest",
          "created_at": "2025-12-17T10:00:00Z"
        },
        "created_at": "2025-12-17T10:30:00Z"
      }
    ]
  }
]
```
⬆️ **It returns all workouts for the user with status "active" or "pending", sorted by created_at in ascending order** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "unauthorized"
}
```
⬆️ **It means JWT token is missing or invalid** ⬆️

```json
{
  "error": "failed to fetch workouts"
}
```
⬆️ **It means there was an error fetching workouts from database** ⬆️

---

### ✏️ Update Workout
**Endpoint:** `PUT /workouts/:workout_id`
- ✅🔐 It requires a JWT token
- ✅🧾 It needs a body JSON

#### 📎 Example Request
```json
{
  "title": "Evening Chest Workout",
  "description": "Updated description",
  "comments": "Added more reps",
  "scheduled_for": "2025-12-18T18:00:00Z",
  "status": "active"
}
```
**Note:** All fields are optional, only send the fields you want to update

#### 🖇️ Example Response
##### ✅ Success Response
```json
{
  "id": 1,
  "title": "Evening Chest Workout",
  "description": "Updated description",
  "status": "active",
  "comments": "Added more reps",
  "scheduled_for": "2025-12-18T18:00:00Z",
  "created_at": "2025-12-17T10:30:00Z",
  "user_id": 1,
  "exercises": [...]
}
```
⬆️ **It means workout has been updated successfully** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "unauthorized"
}
```
⬆️ **It means JWT token is missing or invalid** ⬆️

```json
{
  "error": "workout not found"
}
```
⬆️ **It means the workout doesn't exist or doesn't belong to the user** ⬆️

```json
{
  "error": "invalid workout data"
}
```
⬆️ **It means the request body is not valid JSON** ⬆️

```json
{
  "error": "invalid datetime format"
}
```
⬆️ **It means scheduled_for date format is incorrect** ⬆️

```json
{
  "error": "invalid status value"
}
```
⬆️ **It means status must be "pending" or "active"** ⬆️

---

### 🗑️ Delete Workout
**Endpoint:** `DELETE /workouts/:workout_id`
- ✅🔐 It requires a JWT token
- ❌🧾 It not requires a body JSON

#### 🖇️ Example Response
##### ✅ Success Response
**Status Code:** `204 No Content`

⬆️ **It means workout has been deleted successfully** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "unauthorized"
}
```
⬆️ **It means JWT token is missing or invalid** ⬆️

```json
{
  "error": "workout not found"
}
```
⬆️ **It means the workout doesn't exist or doesn't belong to the user** ⬆️

```json
{
  "error": "failed to delete workout"
}
```
⬆️ **It means there was an error deleting the workout** ⬆️

---

### ➕ Add Exercise to Workout
**Endpoint:** `POST /workouts/:workout_id/exercises`
- ✅🔐 It requires a JWT token
- ✅🧾 It needs a body JSON

#### 📎 Example Request
```json
{
  "exercise_id": 3,
  "sets": 3,
  "repetitions": 15,
  "weight": 0
}
```

#### 🖇️ Example Response
##### ✅ Success Response
```json
{
  "id": 2,
  "workout_id": 1,
  "exercise_id": 3,
  "sets": 3,
  "repetitions": 15,
  "weight": 0,
  "exercise": {
    "id": 3,
    "name": "Push Ups",
    "description": "Bodyweight push exercise",
    "category": "Strength",
    "muscle_group": "Chest",
    "created_at": "2025-12-17T10:00:00Z"
  },
  "created_at": "2025-12-17T11:00:00Z"
}
```
⬆️ **It means exercise has been added to workout successfully** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "unauthorized"
}
```
⬆️ **It means JWT token is missing or invalid** ⬆️

```json
{
  "error": "invalid workout id"
}
```
⬆️ **It means the workout_id parameter is not a valid number** ⬆️

```json
{
  "error": "workout not found or access denied"
}
```
⬆️ **It means the workout doesn't exist or doesn't belong to the user** ⬆️

```json
{
  "error": "invalid exercise data"
}
```
⬆️ **It means the request body is invalid or missing required fields** ⬆️

```json
{
  "error": "exercise not found"
}
```
⬆️ **It means the exercise_id doesn't exist** ⬆️

---

### 📊 Get Exercises for Workout
**Endpoint:** `GET /workouts/:workout_id/exercises`
- ✅🔐 It requires a JWT token
- ❌🧾 It not requires a body JSON

#### 🖇️ Example Response
##### ✅ Success Response
```json
[
  {
    "id": 1,
    "workout_id": 1,
    "exercise_id": 1,
    "sets": 4,
    "repetitions": 12,
    "weight": 80.5,
    "exercise": {
      "id": 1,
      "name": "Bench Press",
      "description": "Barbell chest press",
      "category": "Strength",
      "muscle_group": "Chest",
      "created_at": "2025-12-17T10:00:00Z"
    },
    "created_at": "2025-12-17T10:30:00Z"
  },
  {
    "id": 2,
    "workout_id": 1,
    "exercise_id": 3,
    "sets": 3,
    "repetitions": 15,
    "weight": 0,
    "exercise": {
      "id": 3,
      "name": "Push Ups",
      "description": "Bodyweight push exercise",
      "category": "Strength",
      "muscle_group": "Chest",
      "created_at": "2025-12-17T10:00:00Z"
    },
    "created_at": "2025-12-17T11:00:00Z"
  }
]
```
⬆️ **It returns all exercises in the workout** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "unauthorized"
}
```
⬆️ **It means JWT token is missing or invalid** ⬆️

```json
{
  "error": "invalid workout id"
}
```
⬆️ **It means the workout_id parameter is not a valid number** ⬆️

```json
{
  "error": "workout not found or access denied"
}
```
⬆️ **It means the workout doesn't exist or doesn't belong to the user** ⬆️

---

### 🔄 Update Workout Exercise
**Endpoint:** `PUT /workouts/:workout_id/exercises/:exercise_id`
- ✅🔐 It requires a JWT token
- ✅🧾 It needs a body JSON

#### 📎 Example Request
```json
{
  "sets": 5,
  "repetitions": 10,
  "weight": 85.0
}
```
**Note:** All fields are optional, only send the fields you want to update

#### 🖇️ Example Response
##### ✅ Success Response
```json
{
  "id": 1,
  "workout_id": 1,
  "exercise_id": 1,
  "sets": 5,
  "repetitions": 10,
  "weight": 85.0,
  "exercise": {
    "id": 1,
    "name": "Bench Press",
    "description": "Barbell chest press",
    "category": "Strength",
    "muscle_group": "Chest",
    "created_at": "2025-12-17T10:00:00Z"
  },
  "created_at": "2025-12-17T10:30:00Z"
}
```
⬆️ **It means the workout exercise has been updated successfully** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "unauthorized"
}
```
⬆️ **It means JWT token is missing or invalid** ⬆️

```json
{
  "error": "invalid workout id"
}
```
⬆️ **It means the workout_id parameter is not a valid number** ⬆️

```json
{
  "error": "workout not found or access denied"
}
```
⬆️ **It means the workout doesn't exist or doesn't belong to the user** ⬆️

```json
{
  "error": "exercise entry not found in workout"
}
```
⬆️ **It means the exercise entry doesn't exist in this workout** ⬆️

```json
{
  "error": "invalid data"
}
```
⬆️ **It means the request body is not valid JSON** ⬆️

---

### ❌ Delete Exercise from Workout
**Endpoint:** `DELETE /workouts/:workout_id/exercises/:exercise_id`
- ✅🔐 It requires a JWT token
- ❌🧾 It not requires a body JSON

#### 🖇️ Example Response
##### ✅ Success Response
```json
{
  "message": "exercise removed from workout"
}
```
⬆️ **It means the exercise has been removed from the workout successfully** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "unauthorized"
}
```
⬆️ **It means JWT token is missing or invalid** ⬆️

```json
{
  "error": "invalid workout id"
}
```
⬆️ **It means the workout_id parameter is not a valid number** ⬆️

```json
{
  "error": "workout not found or access denied"
}
```
⬆️ **It means the workout doesn't exist or doesn't belong to the user** ⬆️

```json
{
  "error": "exercise entry not found in workout"
}
```
⬆️ **It means the exercise entry doesn't exist in this workout** ⬆️

```json
{
  "error": "failed to delete exercise from workout"
}
```
⬆️ **It means there was an error deleting the exercise** ⬆️

---

### 📈 Generate Report
**Endpoint:** `GET /workouts/report`
- ✅🔐 It requires a JWT token
- ❌🧾 It not requires a body JSON

#### 🖇️ Example Response
##### ✅ Success Response
```json
[
  {
    "sets": 4,
    "repetitions": 12,
    "weight": 80.5,
    "category": "Strength",
    "muscle_group": "Chest",
    "status": "pending",
    "scheduled_for": "2025-12-18T08:00:00Z"
  },
  {
    "sets": 3,
    "repetitions": 15,
    "weight": 0,
    "category": "Strength",
    "muscle_group": "Chest",
    "status": "active",
    "scheduled_for": "2025-12-18T18:00:00Z"
  },
  {
    "sets": 3,
    "repetitions": 10,
    "weight": 0,
    "category": "Strength",
    "muscle_group": "Back",
    "status": "pending",
    "scheduled_for": "2025-12-19T08:00:00Z"
  }
]
```
⬆️ **It returns a report of all workout exercises for the user with exercise and workout details** ⬆️

##### 🛑 Error Responses
```json
{
  "error": "unauthorized"
}
```
⬆️ **It means JWT token is missing or invalid** ⬆️

```json
{
  "error": "failed to generate report"
}
```
⬆️ **It means there was an error generating the report** ⬆️

---

## 📝 Notes

- **JWT Token Format:** All authenticated endpoints require a JWT token in the Authorization header as `Bearer YOUR_TOKEN`
- **Date Format:** All dates must be in RFC3339 format (e.g., `2025-12-18T08:00:00Z`)
- **Status Values:** Workout status can only be `"pending"` or `"active"`
- **Token Expiry:** JWT tokens expire after 1 hour
- **Workout Exercise ID:** The `exercise_id` in workout exercise endpoints refers to the `WorkoutExercise.ID`, not the `Exercise.ID`

---

## 🔧 Database Configuration

- **Database:** MySQL
- **Host:** localhost:3306
- **Database Name:** workout_database
- **User:** workout_user
- **Password:** Workout_Password$1234

---

## 🏃 Running the Server

```bash
# Set custom port (optional)
export PORT=8080

# Run the server
go run main.go
```

Server will start on `http://localhost:8080` by default.