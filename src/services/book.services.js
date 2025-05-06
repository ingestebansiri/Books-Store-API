import { Book } from "../models/Book.js";

export const getAllBooks = async (req, res) => {
    const books = await Book.findAll();
    if (!books) {
        return res.status(404).send({message: "No se encontraron libros"});
    }
    res.json(books);
}

export const getByID = async (req, res) => {
    const { id } = req.params;
    const book = await Book.findByPk(id);
    if (!book) {
        return res.status(404).send({message: "Libro no encontrado"});
    }
    res.json(book);
}

export const createBook = async (req, res) => {
    const { title, author, rating, pageCount, summary, imageUrl, available } = req.body;
    if (!title || !author) {
        return res.status(400).send({message: "Titulo y autor son requeridos"});
    }
    const newBook = await Book.create({
        title, author, rating, pageCount, summary, imageUrl, available
    });
    res.json(newBook);

};

export const updateBook = async (req, res) => {
    const { title, author, rating, pageCount, summary, imageUrl, available } = req.body;
    const { id } = req.params;
    const book = await Book.findByPk(id);
    if (!book) {
        return res.status(404).send({message: "Libro no encontrado"});
    }
    await book.update({
        title, author, rating, pageCount, summary, imageUrl, available
    });

    res.json(book);
};

export const deleteBook = async (req, res) => {
    const { id } = req.params;
    const book = await Book.findByPk(id);
    if (!book) {
        return res.status(404).send({message: "Libro no encontrado"});
    }
    await book.destroy();
    res.send(`El libro con id ${id} ha sido eliminado correctamente`);
};