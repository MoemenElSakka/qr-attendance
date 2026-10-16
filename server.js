const express = require('express');
const cors = require('cors');
const QRCode = require('qrcode');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this-in-production';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// ========== إعداد قاعدة البيانات ==========
const db = new Database('attendance.db');

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'teacher',
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        approved_at DATETIME,
        approved_by INTEGER
    );
    
    CREATE TABLE IF NOT EXISTS students (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        grade TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT NOT NULL,
        scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES students(id)
    );

    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
`);

// إنشاء مستخدم افتراضي
const adminExists = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!adminExists) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.prepare('INSERT INTO users (username, password, name, role, status) VALUES (?, ?, ?, ?, ?)').run(
        'admin',
        hashedPassword,
        'المدير',
        'admin',
        'approved'
    );
    console.log('✅ تم إنشاء المستخدم الافتراضي: admin / admin123');
}

// ========== Middleware ==========
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'يجب تسجيل الدخول أولاً' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'توكن غير صالح أو منتهي الصلاحية' });
        }
        req.user = user;
        next();
    });
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========== 1. المصادقة ==========

app.post('/api/register', (req, res) => {
    const { username, password, name, email } = req.body;
    if (!username || !password || !name) {
        return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور والاسم مطلوبان' });
    }
    if (username.length < 3) return res.status(400).json({ error: 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل' });
    if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

    const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (existingUser) return res.status(400).json({ error: 'اسم المستخدم موجود مسبقاً' });

    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const result = db.prepare('INSERT INTO users (username, password, name, email, role, status) VALUES (?, ?, ?, ?, ?, ?)').run(username, hashedPassword, name, email || '', 'teacher', 'pending');
        res.json({ message: 'تم إنشاء الحساب بنجاح. سيتم مراجعة طلبك من قبل المدير.', userId: result.lastInsertRowid, status: 'pending' });
    } catch (err) {
        res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الحساب' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

    if (user.status === 'pending') return res.status(403).json({ error: 'حسابك قيد المراجعة.', status: 'pending' });
    if (user.status === 'rejected') return res.status(403).json({ error: 'تم رفض طلبك.', status: 'rejected' });

    const token = jwt.sign({ id: user.id, username: user.username, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ message: 'تم تسجيل الدخول بنجاح', token, user: { id: user.id, username: user.username, name: user.name, role: user.role } });
});

app.get('/api/verify', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// ========== 2. إدارة طلبات التسجيل ==========

app.get('/api/pending-requests', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح لك بالوصول' });
    const requests = db.prepare(`SELECT id, username, name, email, created_at FROM users WHERE status = 'pending' ORDER BY created_at DESC`).all();
    res.json(requests);
});

app.post('/api/pending-requests/:id/approve', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح لك بالوصول' });
    const result = db.prepare(`UPDATE users SET status = 'approved', approved_at = CURRENT_TIMESTAMP, approved_by = ? WHERE id = ? AND status = 'pending'`).run(req.user.id, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'الطلب غير موجود أو تمت معالجته' });
    res.json({ message: 'تم الموافقة على الطلب بنجاح' });
});

app.post('/api/pending-requests/:id/reject', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح لك بالوصول' });
    const result = db.prepare(`UPDATE users SET status = 'rejected', approved_at = CURRENT_TIMESTAMP, approved_by = ? WHERE id = ? AND status = 'pending'`).run(req.user.id, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'الطلب غير موجود أو تمت معالجته' });
    res.json({ message: 'تم رفض الطلب' });
});

app.get('/api/account-status/:username', (req, res) => {
    const user = db.prepare('SELECT id, status FROM users WHERE username = ?').get(req.params.username);
    if (!user) return res.status(404).json({ error: 'الحساب غير موجود' });
    res.json({ status: user.status });
});

// ========== 3. إدارة المستخدمين ==========

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح لك بالوصول' });
    const users = db.prepare('SELECT id, username, name, role, status, created_at FROM users').all();
    res.json(users);
});

app.post('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح لك بالوصول' });
    const { username, password, name, role } = req.body;
    if (!username || !password || !name) return res.status(400).json({ error: 'جميع الحقول مطلوبة' });

    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        db.prepare('INSERT INTO users (username, password, name, role, status) VALUES (?, ?, ?, ?, ?)').run(username, hashedPassword, name, role || 'teacher', 'approved');
        res.json({ message: 'تم إضافة المستخدم بنجاح' });
    } catch (err) {
        if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'اسم المستخدم موجود مسبقاً' });
        res.status(500).json({ error: 'حدث خطأ أثناء إضافة المستخدم' });
    }
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح لك بالوصول' });
    if (req.params.id == req.user.id) return res.status(400).json({ error: 'لا يمكنك حذف حسابك الخاص' });
    const result = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ message: 'تم حذف المستخدم بنجاح' });
});

// ========== 4. إدارة الطلاب ==========

app.get('/api/students', authenticateToken, (req, res) => {
    const { search } = req.query;
    let students;
    if (search) {
        students = db.prepare(`
            SELECT s.*, COUNT(a.id) as attendance_count 
            FROM students s 
            LEFT JOIN attendance a ON s.id = a.student_id 
            WHERE s.id LIKE ? OR s.name LIKE ? OR s.grade LIKE ? 
            GROUP BY s.id 
            ORDER BY s.created_at DESC
        `).all(`%${search}%`, `%${search}%`, `%${search}%`);
    } else {
        students = db.prepare(`
            SELECT s.*, COUNT(a.id) as attendance_count 
            FROM students s 
            LEFT JOIN attendance a ON s.id = a.student_id 
            GROUP BY s.id 
            ORDER BY s.created_at DESC
        `).all();
    }
    res.json(students);
});

app.post('/api/students', authenticateToken, async (req, res) => {
    const { id, name, grade } = req.body;
    if (!id || !name) return res.status(400).json({ error: 'رقم الطالب والاسم مطلوبان' });
    try {
        db.prepare('INSERT INTO students (id, name, grade) VALUES (?, ?, ?)').run(id, name, grade || '');
        const qrImage = await QRCode.toDataURL(id);
        res.json({ message: 'تم إضافة الطالب بنجاح', student: { id, name, grade }, qrImage });
    } catch (err) {
        if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'رقم الطالب موجود مسبقاً' });
        res.status(500).json({ error: 'حدث خطأ أثناء إضافة الطالب' });
    }
});

app.put('/api/students/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, grade } = req.body;
    if (!name) return res.status(400).json({ error: 'الاسم مطلوب' });
    const result = db.prepare('UPDATE students SET name = ?, grade = ? WHERE id = ?').run(name, grade || '', id);
    if (result.changes === 0) return res.status(404).json({ error: 'الطالب غير موجود' });
    res.json({ message: 'تم تعديل بيانات الطالب بنجاح' });
});

app.delete('/api/students/:id', authenticateToken, (req, res) => {
    const result = db.prepare('DELETE FROM students WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'الطالب غير موجود' });
    res.json({ message: 'تم حذف الطالب بنجاح' });
});

app.get('/api/students/:id/qr', authenticateToken, async (req, res) => {
    const student = db.prepare('SELECT * FROM students WHERE id = ?').get(req.params.id);
    if (!student) return res.status(404).json({ error: 'الطالب غير موجود' });
    const qrImage = await QRCode.toDataURL(student.id);
    res.json({ student, qrImage });
});

// ========== 5. تسجيل الحضور ==========

app.post('/api/attendance', authenticateToken, (req, res) => {
    const { studentId } = req.body;
    const student = db.prepare('SELECT * FROM students WHERE id = ?').get(studentId);
    if (!student) return res.status(404).json({ error: 'رقم طالب غير معروف' });

    db.prepare('INSERT INTO attendance (student_id) VALUES (?)').run(studentId);
    const now = new Date();
    res.json({
        studentId: student.id,
        name: student.name,
        grade: student.grade,
        time: now.toLocaleTimeString('ar-EG'),
        date: now.toLocaleDateString('ar-EG'),
        recordedBy: req.user.name
    });
});

// ========== 6. الإحصائيات والسجلات ==========

app.get('/api/stats', authenticateToken, (req, res) => {
    const totalStudents = db.prepare('SELECT COUNT(*) as count FROM students').get().count;
    const today = new Date().toISOString().split('T')[0];
    const todayAttendance = db.prepare(`SELECT COUNT(DISTINCT student_id) as count FROM attendance WHERE DATE(scan_time) = ?`).get(today).count;
    const totalRecords = db.prepare('SELECT COUNT(*) as count FROM attendance').get().count;
    res.json({ totalStudents, todayAttendance, totalRecords });
});

app.get('/api/attendance', authenticateToken, (req, res) => {
    const { date } = req.query;
    let records;
    if (date) {
        records = db.prepare(`
            SELECT a.scan_time, s.id, s.name, s.grade,
            (SELECT COUNT(*) FROM attendance WHERE student_id = s.id) as total_attendance
            FROM attendance a 
            JOIN students s ON a.student_id = s.id 
            WHERE DATE(a.scan_time) = ? 
            ORDER BY a.scan_time DESC
        `).all(date);
    } else {
        const today = new Date().toISOString().split('T')[0];
        records = db.prepare(`
            SELECT a.scan_time, s.id, s.name, s.grade,
            (SELECT COUNT(*) FROM attendance WHERE student_id = s.id) as total_attendance
            FROM attendance a 
            JOIN students s ON a.student_id = s.id 
            WHERE DATE(a.scan_time) = ? 
            ORDER BY a.scan_time DESC
        `).all(today);
    }
    const formatted = records.map(r => ({
        ...r,
        time: new Date(r.scan_time).toLocaleTimeString('ar-EG'),
        date: new Date(r.scan_time).toLocaleDateString('ar-EG')
    }));
    res.json(formatted);
});

// ========== 7. الإعدادات ==========

app.get('/api/settings', (req, res) => {
    const settings = {};
    db.prepare('SELECT * FROM settings').all().forEach(row => { settings[row.key] = row.value; });
    res.json(settings);
});

app.post('/api/settings', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح لك بالوصول' });
    try {
        const insert = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
        Object.entries(req.body).forEach(([key, value]) => { insert.run(key, value); });
        res.json({ message: 'تم حفظ الإعدادات بنجاح' });
    } catch (err) {
        res.status(500).json({ error: 'حدث خطأ أثناء حفظ الإعدادات' });
    }
});

// ========== 8. تغيير كلمة المرور ==========

app.post('/api/change-password', authenticateToken, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'كلمة المرور الحالية والجديدة مطلوبتان' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل' });

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!bcrypt.compareSync(currentPassword, user.password)) return res.status(401).json({ error: 'كلمة المرور الحالية غير صحيحة' });

    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, req.user.id);
    res.json({ message: 'تم تغيير كلمة المرور بنجاح' });
});

app.post('/api/reset-password', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مصرح لك بالوصول' });
    const { userId, newPassword } = req.body;
    if (!userId || !newPassword) return res.status(400).json({ error: 'معرف المستخدم وكلمة المرور الجديدة مطلوبان' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });

    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, userId);
    res.json({ message: `تم إعادة تعيين كلمة المرور لـ ${user.name} بنجاح` });
});

// ========== 9. معلومات التاريخ ==========

app.get('/api/today-info', authenticateToken, (req, res) => {
    const now = new Date();
    res.json({
        date: now.toLocaleDateString('ar-EG', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }),
        fullDate: now.toLocaleDateString('ar-EG'),
        time: now.toLocaleTimeString('ar-EG'),
        dayOfWeek: now.toLocaleDateString('ar-EG', { weekday: 'long' }),
        year: now.getFullYear(),
        month: now.getMonth() + 1,
        day: now.getDate()
    });
});

app.listen(PORT, () => {
    console.log(`🚀 السيرفر يعمل على: http://localhost:${PORT}`);
    console.log(`📂 قاعدة البيانات محفوظة في: attendance.db`);
    console.log(`👤 المستخدم الافتراضي: admin / admin123`);
});