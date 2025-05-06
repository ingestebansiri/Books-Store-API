import { Router } from "express";
import { getAllBooks, getByID, createBook, updateBook, deleteBook } from "../services/book.services.js";

const router = Router();

router.get("/books", getAllBooks);

router.get("/books/:id", getByID);

router.post("/books", createBook);

router.put("/books/:id", updateBook);

router.delete("/books/:id", deleteBook);

export default router;