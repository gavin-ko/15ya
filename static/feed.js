$(document).ready(function(){
    init()
    get_feeds()
});

function get_feeds(){
    $.ajax({
        type: "GET",
        url: "/api/feed_upload",
        data: {
        },
        success: function (response) {
        },
    });
}

// 초기화 함수
function init(){
    $('#modal-container').hide()
    $('.modal_wrap_write_wrap').hide()
    $('#modal_upload').hide()
    $('#modal_next').show()
    $('.modal_wrap_content_wrap').show()

    $('.modal_wrap').css({
        width: "700px",

    })
    $('.modal_wrap_write_content_left').css({
        "background-image": "none"
    })
    $('#modal_upload').css({
        color: '#fff'
    })
    $('#write_content').val(null)
}

// 모달 실행
$('#feed_upload').click(function() {
    $('#modal-container').show()
})

// 모달 종료
$('#modal_close_').click(function() {
    init()
})

// 모달 이미지 올리기 & 올린 후 작성 모달변경
$('.modal_wrap_content_wrap')
            .on("dragover", dragOver)
            .on("dragleave", dragOver)
            .on("drop", uploadFiles)
        
            function dragOver(event){
                event.stopPropagation();
                event.preventDefault();

                if (event.type == "dragover") {
                    document.getElementById("modal_content_image").src ="../static/icons/imagegallery_on.png"
                } else {
                    document.getElementById("modal_content_image").src ="../static/icons/imagegallery.png"
                }
            }

            function uploadFiles(event){
                event.stopPropagation();
                event.preventDefault()

                event.dataTransfer = event.originalEvent.dataTransfer;
                files = event.target.files || event.dataTransfer.files;
                console.log("Test:" + files[0].name)

                if (files.length > 1) {
                    alert ('One File Only.');
                    return;
                }

                if (files[0].type.match(/image.*/)) {
                    $('.modal_wrap').css({
                        width: "960px",
  
                    })
                    $('.modal_wrap_write_content_left').css({
                        "background-image": "url("+ window.URL.createObjectURL(files[0]) + ")",
                        "outline": "none",
                        "background-size": "100%",
                        "background-position": "center",
                        "background-repeat": "no-repeat"
                    })
                    $('.modal_wrap_content_wrap').hide()
                    $('.modal_wrap_write_wrap').show()
                    
                    $('#modal_upload').show()
                    $('#modal_next').hide()
                    $('#modal_upload').css({
                        color: '#0095f6',
                        cursor: 'pointer',
                    })

                } else {
                    alert('이미지가 아닙니다.')
                    return;
                }
            }
    
$('#modal_upload').click(function(){
    let file = files[0] 
    let image = files[0].name
    let content = $('#write_content').val()
    let fd = new FormData()
    fd.append('file',file);
    fd.append('image',image);
    fd.append('content',content);

    $.ajax({
        url: '/api/feed_upload',
        data: fd,
        method: "POST",
        processData: false,
        contentType: false,
        success: function (response){
            if (response['result'] == 'success'){
                alert(response['msg'])
                window.location.replace('/')
            } else {
                alert('업로드 실패입니다.')
            }
        }
    })
})


function feed_delete(index){
    $.ajax({
        type: "POST",
        url: "/api/feed_delete",
        data: {
            index_give:index
        },
        success: function (response) {
            if (response['result'] == 'success') {
                alert(response['msg'])
                window.location.replace("/")
            }
            else{
                alert(response['msg'])
                window.location.replace("/")

            }
        },
    });
    
}