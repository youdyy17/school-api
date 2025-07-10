import db from '../models/index.js';

/**
 * @swagger
 * tags:
 *   name: Students
 *   description: Student management
 */

export const createStudent = async (req, res) => {
    try {
        const student = await db.Student.create(req.body);
        res.status(201).json(student);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * @swagger
 * /students:
 *   get:
 *     summary: Get all students
 *     tags: [Students]
 *     parameters: 
 *       - in: query
 *         name: page
 *         schema: { type:integer, default:1 }
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 100}
 *         description: Number of items per page
 *       - in: query
 *         name: sort
 *         enum: [asc,desc]
 *         default: desc
 *         description: "Sort order for results. asc = oldest first, desc = newest first. Sorted by created time."
 *       - in: query
 *         name: sortBy
 *         schema:
 *           type: string
 *           enum: [createdAt, name, email] # Add all sortable fields here
 *           default: createdAt
 *     responses:
 *       200:
 *         description: List of students
 */
export const getAllStudents = async (req, res) => {
    const limit = parseInt(req.query.limit) || 200;
    const total = await db.Student.count();

    const page = parseInt(req.query.page) || 1;
    const sortOrder = req.query.sort === 'asc' ? 'ASC' : 'DESC';
    const sortBy = req.query.sortBy || 'createdAt';
    try {
        const students = await db.Student.findAll(
            {
                include: db.Course,
                limit: limit,
                offset: (page - 1) * limit,
                order: [[sortBy, sortOrder]]
            });
        res.json(students);

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * @swagger
 * /students/{id}:
 *   get:
 *     summary: Get a student by ID
 *     tags: [Students]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: A student
 *       404:
 *         description: Not found
 */
export const getStudentById = async (req, res) => {
    try {
        const student = await db.Student.findByPk(req.params.id, { include: db.Course });
        if (!student) return res.status(404).json({ message: 'Not found' });
        res.json(student);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * @swagger
 * /students/{id}:
 *   put:
 *     summary: Update a student
 *     tags: [Students]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema: { type: integer }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema: { type: object }
 *     responses:
 *       200:
 *         description: Updated
 */
export const updateStudent = async (req, res) => {
    try {
        const student = await db.Student.findByPk(req.params.id);
        if (!student) return res.status(404).json({ message: 'Not found' });
        await student.update(req.body);
        res.json(student);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

/**
 * @swagger
 * /students/{id}:
 *   delete:
 *     summary: Delete a student
 *     tags: [Students]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Deleted
 */
export const deleteStudent = async (req, res) => {
    try {
        const student = await db.Student.findByPk(req.params.id);
        if (!student) return res.status(404).json({ message: 'Not found' });
        await student.destroy();
        res.json({ message: 'Deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
