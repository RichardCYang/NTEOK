const fs = require('fs');
const path = require('path');

module.exports = function(dependencies) {
    const { express, authMiddleware, themeUpload } = dependencies;
    const router = express.Router();

    router.get('/', authMiddleware, (req, res) => {
        const themesDirectory = path.join(__dirname, '..', 'themes');
        fs.readdir(themesDirectory, (err, files) => {
            if (err) {
                console.error("Could not list the directory.", err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            const themeFiles = files.filter(file => file.endsWith('.css')).map(file => {
                return {
                    name: path.basename(file, '.css'),
                    path: `/themes/${file}`
                };
            });
            
            res.json(themeFiles);
        });
    });

    router.post('/upload', authMiddleware, themeUpload.single('themeFile'), (req, res) => {
        if (!req.file) {
            return res.status(400).json({ error: '파일이 업로드되지 않았습니다.' });
        }
        res.json({
            message: '테마가 성공적으로 업로드되었습니다.',
            theme: {
                name: path.basename(req.file.filename, '.css'),
                path: `/themes/${req.file.filename}`
            }
        });
    });

    /**
     * 사용자 테마 설정 저장
     * POST /api/themes/set
     */
    router.post('/set', authMiddleware, async (req, res) => {
        const { theme } = req.body;
        const userId = req.user.id;

        if (!theme) {
            return res.status(400).json({ error: '테마 이름이 필요합니다.' });
        }

        try {
            await dependencies.pool.execute(
                'UPDATE users SET theme = ? WHERE id = ?',
                [theme, userId]
            );
            res.json({ success: true, message: '테마 설정이 저장되었습니다.' });
        } catch (error) {
            dependencies.logError('POST /api/themes/set', error);
            res.status(500).json({ error: '테마 저장 중 오류가 발생했습니다.' });
        }
    });

    return router;
};
