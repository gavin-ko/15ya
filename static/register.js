function register() {
    let email = $('#email').val()
    let name = $('#name').val()
    let nickname = $('#nickname').val()
    let password = $('#pw').val()

    $.ajax({
            type: "POST",
            url: "/register",
            data: {
                email_give: email,
                name_give: name,
                nickname_give: nickname,
                password_give : password
            },
            success: function (response) {
                if (response['result'] == 'failed') {
                    alert(response['msg'])
                }
                else{
                    alert("회원가입을 축하드립니다!")
                    window.location.replace("/login")
                }
            },
        });
}