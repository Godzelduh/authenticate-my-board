import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());

interface User {
    username: string;
    password: string;
}

const users: User[] = []; // This should be replaced with a real database

// Middleware to authenticate token
function authenticateToken(req: express.Request, res: express.Response, next: express.NextFunction): void {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET as string, (err: any, user: any): void => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Register route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).send('User registered');
});

// Login route
app.post('/login', async (req, res): Promise<void> => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(403).send('Invalid credentials');
    }

    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET as string, { expiresIn: '1h' });
    res.json({ token });
});

// Protected route example
app.get('/tickets', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route for tickets', user: req.user });
});

// Another protected route example
app.get('/users', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route for users', user: req.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});