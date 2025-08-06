const User = require('../models/User');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');

const generateToken = (user) =>{
    return jwt.sign(
        {id: user._id, role:user.role},
        process.env.JWT_SECRET,
        { expiresIn: '1d'}
    );
};

exports.register = async (req,res) => {
    try{
        const {name,email,password,role} = req.body;
        const user = await User.create({name,email,password,role});
        const token = generateToken(user);
        res.status(201).json({user,token});
    }
    catch(err){
        res.status(400).json({error: err.message});
    }
};

exports.login = async (req,res) =>{
    try{
        const {email,password} = req.body;
        const user = await User.findOne({email});
        if(!user || !(await user.comparePassword(password))){
            return res.status(401).json({error: 'Invalid credentials'})
        }
        const token = generateToken(user);
        res.status(200).json({user,token});
    } catch(err){
        res.status(400).json({error: err.message})
    };
};

exports.forgotPassword = async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const resetToken = user.generateResetToken();
  await user.save({ validateBeforeSave: false });

  const resetUrl = `${req.protocol}://${req.get('host')}/api/auth/reset-password/${resetToken}`;
  const message = `<p>Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 10 minutes.</p>`;

  try {
    await sendEmail(user.email, 'Password Reset', message);
    res.status(200).json({ message: 'Reset email sent' });
  } catch (err) {
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save({ validateBeforeSave: false });
    res.status(500).json({ error: 'Email failed to send' });
  }
};

exports.resetPassword = async (req, res) => {
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpire: { $gt: Date.now() }
  });

  if (!user) return res.status(400).json({ error: 'Token is invalid or expired' });

  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save();

  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.status(200).json({ message: 'Password reset successful', token });
};

exports.getAllUsersWithRoleStats = async (req, res) => {
  try {
    const roleCounts = await User.aggregate([
      {
        $group: {
          _id: "$role",
          count: { $sum: 1 }
        }
      }
    ]);

    res.status(200).json({
      success: true,
      data: roleCounts
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
};

exports.getUsersByRole = async (req, res) => {
  try {
    const role = req.query.role;
    const users = await User.find({ role }).select("name role");

    res.status(200).json({
      success: true,
      data: users
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
};


// Example protected route
exports.superAdminDashboard = (req, res) => {
  res.status(200).json({ message: 'Welcome Super Admin!' });
};

exports.adminDashboard = (req, res) => {
  res.status(200).json({ message: 'Welcome Admin!' });
};

exports.clientDashboard = (req, res) => {
  res.status(200).json({ message: 'Welcome Client!' });
};

