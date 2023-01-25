import User from "../models/user";
import { hashPassword, comparePassword } from "../helpers/auth";
import jwt from "jsonwebtoken";
const crypto = require("crypto")
const sendEmail = require("../utils/sendMail");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

export const register = async (req, res) => {
  try {
    // validation
    const { username, email, password } = req.body;
    if (!username) {
      return res.json({
        error: "username is required",
      });
    }
    if (!password || password.length < 6) {
      return res.json({
        error: "Password is required and should be 6 characters long",
      });
    }
    const exist = await User.findOne({ email });
    if (exist) {
      return res.json({
        error: "Email is taken",
      });
    }
    // hash password
    const hashedPassword = await hashPassword(password);

    // create account in stripe
    const customer = await stripe.customers.create({
      email,
    });
    // console.log("stripe customer created on signup", customer);

    try {
      const user = await new User({
        username,
        email,
        password: hashedPassword,
        stripe_customer_id: customer.id,
      }).save();

      // create signed token
      const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });

      //   console.log(user);
      const { password, ...rest } = user._doc;
      return res.json({
        token,
        user: rest,
      });
    } catch (err) {
      console.log(err);
    }
  } catch (err) {
    console.log(err);
  }
};

export const login = async (req, res) => {
  try {
    // check email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.json({
        error: "No user found",
      });
    }
    // check password
    const match = await comparePassword(req.body.password, user.password);
    if (!match) {
      return res.json({
        error: "Wrong password",
      });
    }
    // create signed token
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    const { password, ...rest } = user._doc;

    res.json({
      token,
      user: rest,
    });
  } catch (err) {
    console.log(err);
  }
};


export const forgot = async(req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if(!user) {
      return res.status(404).json({ error: "Wrong email" })
    }
  
    user.resetPasswordToken = crypto.randomBytes(20).toString("hex");
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save()
  
    const resetURL = `${process.env.CLIENT_URL}/passwordreset/${user.resetPasswordToken}`;
    // res.json({ message: `You have been emailed a link. ${resetURL}` })
    const mailText = `
      <h3>Hei ${user.username}</h3>

      <p>Du har nettopp prøvd å fornyet ditt password. Hvis dette er riktig følg linken under</p>
      <a href=${resetURL} clicktracking=off>Link</a>
      <p>Hvis dette er feil, se bort ifra denne mailen.</p>
    `
    await sendEmail(user.email, "Password reset", mailText);
    res.status(200).json({ success: true, data: "Email Sent" });
    } catch (error) {
      console.log(error)    
    }
}

export const reset = async(req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    })
    if(!user) {
      return res.status(400).json({ success: false, data: "Password reset is invalid or has expired" });
    }
  } catch (error) {
    console.log(error)
  }
}

export const confirmedPassword = async(req, res, next) => {
  try {
    if(req.body.password === req.body.confirmpassword) {
      next()
      return
    }
    res.status(400).json({ success: false, data: "Password dont match!" })
  } catch (error) {
    console.log(error)
  }
}

export const update = async(req, res) => {
  console.log("update method called");
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    }, {new: true});
    if(!user) {
      return res.status(400).json({ success: false, data: "Password reset is invalid or has expired" });
    }

    const hashedPassword = await hashPassword(req.body.password);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save()

    res.json({ success: true, data: "Password updated successfully" })
  } catch (err) {
    console.error(err)
    return res.status(500).json({ success: false, data: "An error occured while saving the new password" })
  }
}