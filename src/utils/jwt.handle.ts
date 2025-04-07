import pkg from "jsonwebtoken";
const { sign, verify } = pkg;   //Importamos las funciones sign y verify de la librería jsonwebtoken
const JWT_SECRET = process.env.JWT_SECRET || "token.010101010101";

//No debemos pasar información sensible en el payload, en este caso vamos a pasar como parametro el ID del usuario
const generateToken = (id: string, role: string, name: string) => {
    const jwt = sign({ id, role, name }, JWT_SECRET, { expiresIn: '20s' });
    return jwt;
};

const generateRefreshToken = (id: string) => {
    const refreshToken = sign({ id }, JWT_SECRET, { expiresIn: '7d' }); // Durada de 7 dies
    return refreshToken;
};

const verifyRefreshToken = (refreshToken: string) => {
    try {
        const isOk = verify(refreshToken, JWT_SECRET);
        return isOk;
    } catch (error) {
        return null; // Retornem null si el token no és vàlid
    }
};


const verifyToken = (jwt: string) => {
    const isOk = verify(jwt, JWT_SECRET);
    return isOk;

};

const refreshAccessToken = (refreshToken: string) => {
    const payload = verifyRefreshToken(refreshToken);
    if (!payload) {
        throw new Error("Invalid refresh token");
    }

    // Generem un nou access token amb les dades del payload
    const { id } = payload as { id: string };
    const newAccessToken = generateToken(id, "user", "John Doe"); // Exemple de dades
    return newAccessToken;
};



export { generateToken, verifyToken, generateRefreshToken, verifyRefreshToken, refreshAccessToken };