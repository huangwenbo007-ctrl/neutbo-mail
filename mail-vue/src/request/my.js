import http from '@/axios/index.js';

export function loginUserInfo() {
    return http.get('/my/loginUserInfo')
}

export function resetPassword(password) {
    return http.put('/my/resetPassword', {password})
}

export function requestDeletion(password) {
    return http.post('/my/delete/request', {password, confirmation:'DELETE'})
}

