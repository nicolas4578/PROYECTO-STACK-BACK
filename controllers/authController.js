import mongoose from "mongoose";
import User from "../entities/user.entity.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

if (!process.env.JWT_SECRET) {
    console.error("JWT_SECRET no está definida en el archivo .env");
    process.exit(1);  // Terminar la aplicación si la clave secreta no está definida
}

// Función para generar un token
const generarToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });  // Expiración de 30 días
};

export const userRegister = async (req, res) => {
    const { firstName, lastName, email, password, isAdmin } = req.body;

    const vUser = await User.findOne({ email });

    if (vUser) {
        return res.status(400).json({ message: "Ya existe el usuario" });
    }

    // Encriptar la contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({
        ...req.body,
        password: hashedPassword,  
    });

    // Generar el token para el nuevo usuario
    const token = generarToken(newUser._id);

    // Devolver solo el token, el id y el nombre (firstName y lastName)
    res.status(201).json({
        token,
        id: newUser._id,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
    });
};

export const loginUser = async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    // Verificar si el usuario existe y comparar la contraseña
    if (user) {
        if (await bcrypt.compare(password, user.password)) {
            const token = generarToken(user._id);  // Generar token para el login

            res.status(200).json({
                token,
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName
            });
        } else {
            res.status(400).send("Credenciales inválidas");
        }
    } else {
        res.status(404).json({
            message: "Credenciales inválidas"
        });
    }
};
