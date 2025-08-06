const express = require('express');
const router = express.Router();
const {
  register,
  login,
  forgotPassword,
  resetPassword,
  getAllUsersWithRoleStats,
  getUsersByRole ,
  superAdminDashboard,
  adminDashboard,
  clientDashboard
} = require('../controllers/authController');

const { protect, authorizeRoles } = require('../middleware/authMiddleware');


router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);
router.get('/users',protect,authorizeRoles('SuperAdmin'),getAllUsersWithRoleStats);
router.get('/users-by-role', protect, authorizeRoles('SuperAdmin'), getUsersByRole);


router.get('/super-admin/dashboard', protect, authorizeRoles('SuperAdmin'), superAdminDashboard);
router.get('/admin/dashboard', protect, authorizeRoles('Admin'), adminDashboard);
router.get('/client/dashboard', protect, authorizeRoles('Client'), clientDashboard);

module.exports = router;