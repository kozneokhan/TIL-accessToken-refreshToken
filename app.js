import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

const app = express();
const PORT = 3019;

const ACCESS_TOKEN_SECRET_KEY = `HangHae99`; // Access Token의 비밀 키를 정의합니다.
const REFRESH_TOKEN_SECRET_KEY = `Sparta`; // Refresh Token의 비밀 키를 정의합니다.

app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
    return res.status(200).send('Hello token!');
});

const tokenStorages = {}; // RefreshToken을 관리할 객체
// Access, RefreshToken 발급 API
app.post('/tokens', async (req, res) => {
    //ID 전달
    const { id } = req.body;

    //Access Token과 RefreshToken을 발급
    const accessToken = createAccessToken(id);
    const refreshToken = jwt.sign({ id: id }, REFRESH_TOKEN_SECRET_KEY, { expiresIn: '7d' });

    tokenStorages[refreshToken] = {
        id: id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
    };

    console.log(tokenStorages);

    // 클라이언트에게 쿠키(토큰)을 할당
    res.cookie('accessToken', accessToken);
    res.cookie('refreshToken', refreshToken);

    return res.status(200).json({ message: 'Token이 정상적으로 발급되었습니다.' });
});

// Access Token 검증 API
app.get('/tokens/validate', async (req, res) => {
    const { accessToken } = req.cookies;

    // Access Token이 존재하는지 확인
    if (!accessToken) {
        return res.status(400).json({ errorMessage: 'AccessToken이 존재하지 않습니다.' });
    }

    const payLoad = validateToken(accessToken, ACCESS_TOKEN_SECRET_KEY);
    if (!payLoad) {
        return res.status(401).json({ errorMessage: 'AccessToken이 정상적이지 않습니다.' });
    }

    const { id } = payLoad;
    return res.status(200).json({ message: `${id}의 Payload를 가진 Token이 정상적으로 인증 되었습니다.` });
});

// Token을 검증하고, Payload를 조회하기 위한 함수
function validateToken(token, secretKey) {
    try {
        return jwt.verify(token, secretKey);
    } catch (error) {
        return null;
    }
}

function createAccessToken(id) {
    const accessToken = jwt.sign({ id }, ACCESS_TOKEN_SECRET_KEY, { expiresIn: '10s' });
}

// RefreshToken을 이용해서, AccessToken을 재발급하는 API
app.post('/tokens/refresh', async (req, res) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        return res.status(400).json({ errorMessage: 'RefreshToken이 존재하지 않습니다.' });
    }

    const payLoad = validateToken(refreshToken, REFRESH_TOKEN_SECRET_KEY);
    if (!payLoad) {
        return res.status(401).json({ errorMessage: 'RefreshToken이 정상적이지 않습니다.' });
    }

    const userInfo = tokenStorages[refreshToken];

    if (!userInfo) {
        return res.status(419).json({ errorMessage: 'RefreshToken의 정보가 서버에 존재하지 않습니다.' });
    }

    const newAccessToken = createAccessToken(userInfo.id);

    res.cookie('accessToken', newAccessToken);
    return res.status(200).json({ message: 'AccessToken을 정상적으로 새롭게 발급했습니다.' });
});

app.listen(PORT, () => {
    console.log(PORT, '포트로 서버가 열렸습니다.');
});
