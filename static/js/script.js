'use strict';

(function() {
    let input = document.getElementById("input")
    let output = document.getElementById("output")
    let req = document.getElementById("req")

    const socket = new WebSocket("ws://localhost:80/echo")

    const send = () => {
        let time = new Date()
        socket.send(input.value);
        req.innerHTML += `<div class="container-chat d-flex justify-content-between align-items-cente"><p class="m-0">${input.value}</p><span class="time-right">${time.getTime()}</span></div>`
        input.value = ""
    }

    socket.onopen = function () {
        let time = new Date()
        output.innerHTML += `<div class="container-chat darker d-flex justify-content-between align-items-center"><p class="m-0">Status: Connected</p><span class="time-left">${time.getTime()}</span></div>`;
    }

    socket.onmessage = function (e) {
        let time = new Date()
        output.innerHTML += `<div class="container-chat darker d-flex justify-content-between align-items-center"><p class="m-0">Server: ${e.data}</p><span class="time-left">${time.getTime()}</span></div>`;
    }

    document.querySelector("button").addEventListener("click", function () {
        send()
    })
})()
