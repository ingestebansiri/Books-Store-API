import { Router } from "express";
import { getAllBooks, getByID, createBook, updateBook, deleteBook } from "../services/book.services.js";
import { verifyToken } from "../services/auth.services.js";

const router = Router();

router.get("/books", verifyToken, getAllBooks);

router.get("/books/:id", verifyToken, getByID);

router.post("/books", verifyToken, createBook);

router.put("/books/:id", verifyToken, updateBook);

router.delete("/books/:id", verifyToken, deleteBook);

export default router;