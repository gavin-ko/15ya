function login() {
    let email = $('#email').val()
    let password = $('#pw').val()

    $.ajax({
            type: "POST",
            url: "/login",
            data: {
                email_give: email,
                password_give : password
            },
            success: function (response) {
                if (response['result'] == 'failed') {
                    alert(response['msg'])
                }
                else{
                    $.cookie('15ya_token', response['token'], {path: '/'});
                    window.location.replace('/')
                }

            },
        });
}
