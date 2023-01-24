import express from "express";

const router = express.Router();

import { 
    register, 
    login, 
    forgot, 
    reset, 
    confirmedPassword, 
    update, 
} from "../controllers/auth";

router.post("/register", register);
router.post("/login", login);
router.post("/forgotpassword", forgot); // du skriver inn mail adresse som sender link til mail
router.get("/passwordreset/:token", reset); // henter reset form page
router.patch("/passwordreset/:token", confirmedPassword, update); // reset form som du skriver inn ny password & sjekk ut patch/put


module.exports = router;
