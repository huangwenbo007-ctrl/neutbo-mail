import http from '@/axios/index.js';

export function loginUserInfo() {
    return http.get('/my/loginUserInfo')
}

export function resetPassword(oldPassword, password) {
    return http.put('/my/resetPassword', {oldPassword, password})
}

export function requestDeletion(password) {
    return http.post('/my/delete/request', {password, confirmation:'DELETE'})
}

export function startGoogleDeletion() {
    return http.post('/my/delete/google/start', {})
}

export function completeGoogleDeletion(code, state) {
    return http.post('/my/delete/google/complete', {code, state, confirmation:'DELETE'})
}

