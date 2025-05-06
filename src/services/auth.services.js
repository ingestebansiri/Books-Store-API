import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";
import { User } from "../models/User.js";


export const registerUser = async (req, res) => {
    // Extrae name, email y password del body de la request
    const { name, email, password } = req.body;

    // Busca si ya existe un usuario con ese email
    const user = await User.findOne({
        where: { email }
    });

    // Si existe, devuelve error 400
    if (user)
        return res.status(400).send({ message: "Este email ya se encuentra registrado." });

    // Configura 10 rondas de salt (costo computacional)
    const saltRounds = 10;

    // Genera un salt único
    const salt = await bcrypt.genSalt(saltRounds);

    // Hashea la contraseña con el salt
    const hashedPassword = await bcrypt.hash(password, salt);

    // Crea el nuevo usuario en la base de datos
    const newUser = await User.create({
        name,
        email,
        password: hashedPassword, // Guarda el hash, no la contraseña en texto plano
    });

    // Devuelve solo el ID del nuevo usuario
    res.json(newUser.id);
}

export const loginUser = async (req, res) => {
    // Extrae email y password del body de la request
    const { email, password } = req.body;

    // Busca el usuario por email
    const user = await User.findOne({
        where: { email }
    });

    // Si no existe, devuelve error 401 (No autorizado)
    if (!user)
        return res.status(401).send({ message: "Usuario no existente" });

    // Compara la contraseña ingresada con el hash almacenado
    const comparison = await bcrypt.compare(password, user.password);

    // Si no coinciden, devuelve error 401
    if (!comparison)
        return res.status(401).send({ message: "Email y/o contraseña incorrecta" });

    // Clave secreta para firmar el token (debería estar en variables de entorno)
    const secretKey = 'programacion3-2025';

    // Genera un token JWT que expira en 1 hora
    const token = jwt.sign({ email }, secretKey, { expiresIn: '1h' });

    // Devuelve el token al cliente
    return res.json(token);
}