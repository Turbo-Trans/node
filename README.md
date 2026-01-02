# 🚛 Logistics & Warehouse Management API

A robust RESTful API built with **Node.js**, **Express**, and **MySQL**. This system handles user authentication, role-based access control (RBAC), warehouse inventory tracking, and fleet (truck) management.

![CI/CD](https://img.shields.io/badge/CI%2FCD-Automated-blue)
![Node.js](https://img.shields.io/badge/Node.js-v14+-green)
![Express](https://img.shields.io/badge/Express-4.x-lightgrey)
![MySQL](https://img.shields.io/badge/MySQL-8.0-orange)

## 🚀 Key Features

* **Secure Authentication:** JWT-based session management with UUIDs and Bcrypt password hashing.
* **Role-Based Access Control (RBAC):** Middleware (`perm`) to restrict endpoints based on user permission levels.
* **Transactional Integrity:** Uses MySQL transactions (ACID compliance) for critical operations like User Deletion to prevent data inconsistency.
* **Advanced Filtering & Pagination:** Dynamic query building for listing users, warehouses, and trucks with support for offsets and limits.
* **Entity Management:** Full CRUD operations for:
    * Users & User Data
    * Warehouses (Cities/Countries association)
    * Truck Models & Active Fleet (TruckInfo)
    * Products & Dimensions

## 🔄 CI/CD Pipeline

This project utilizes a Continuous Integration and Continuous Deployment (CI/CD) pipeline to ensure code quality and seamless delivery.

* **Continuous Integration (CI):**
    * Automated linting and syntax checks on every push.
    * Unit tests are triggered to verify authentication logic and database connectivity before merging.
* **Continuous Deployment (CD):**
    * Upon merging to the `main` branch, the application is automatically containerized (Docker).
    * The latest build is deployed to the staging/production server using automated workflows.
    * Includes automatic database migration checks to ensure schema consistency.

## 🛠️ Tech Stack

* **Runtime:** Node.js
* **Framework:** Express.js
* **Database:** MySQL (using `mysql2` with promise support)
* **Security:** `bcrypt`, `jsonwebtoken`, `cors`
* **Utilities:** `uuid`, `body-parser`

## 📡 API Endpoints

### 🔐 Authentication
* `POST /login` - Authenticate user and receive JWT.
* `POST /logout` - Invalidate the current session token.

### 👤 User Management (Admin Only)
* `GET /getUsers` - List users with filtering (by job, city, warehouse) and pagination.
* `POST /addUser` - Create a new user with password complexity checks.
* `DELETE /deleteUser` - Transactional deletion of user and associated data.

### 🏭 Warehouse Operations
* `GET /getWH` - List warehouses.
* `POST /addWH` - Add a new warehouse.
* `PUT /editWH` - Update warehouse details.
* `DELETE /deleteWH` - Remove a warehouse (checks for existing dependencies).
* `GET /getCountries` & `/getCities` - Helper endpoints for location data.

### 🚚 Fleet Management
* **Models:**
    * `POST /addTruck` - Add a truck brand/model.
    * `GET /listTrucks` - List available truck models.
    * `DELETE /removeTruck` - Delete a truck model.
* **Active Fleet (Plates):**
    * `POST /addTruckInfo` - Register a specific vehicle plate to a model.
    * `PUT /editTruckInfo` - Update vehicle details.
    * `GET /listTruckInfo` - List active vehicles.
    * `DELETE /removeTruckInfo` - Remove a vehicle from the fleet.

### 📦 Product Management
* `GET /listProducts` - View inventory details.
* `PUT /editProduct` - Update product dimensions, weight, and status.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
