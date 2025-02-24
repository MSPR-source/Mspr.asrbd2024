
(function ($) {
    "use strict";


    /*==================================================================
    [ Focus input ]*/
    $('.input100').each(function(){
        $(this).on('blur', function(){
            if($(this).val().trim() != "") {
                $(this).addClass('has-val');
            }
            else {
                $(this).removeClass('has-val');
            }
        })    
    })
  
  
    /*==================================================================
    [ Validate ]*/
    var input = $('.validate-input .input100');

    $('.validate-form').on('submit',function(){
        var check = true;

        for(var i=0; i<input.length; i++) {
            if(validate(input[i]) == false){
                showValidate(input[i]);
                check=false;
            }
        }

        return check;
    });


    $('.validate-form .input100').each(function(){
        $(this).focus(function(){
           hideValidate(this);
        });
    });

    function validate (input) {
        if($(input).attr('type') == 'email' || $(input).attr('name') == 'email') {
            if($(input).val().trim().match(/^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/) == null) {
                return false;
            }
        }
        else {
            if($(input).val().trim() == ''){
                return false;
            }
        }
    }

    function showValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).addClass('alert-validate');
    }

    function hideValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).removeClass('alert-validate');
    }
    
    /*==================================================================
    [ Show pass ]*/
    var showPass = 0;
    $('.btn-show-pass').on('click', function(){
        if(showPass == 0) {
            $(this).next('input').attr('type','text');
            $(this).addClass('active');
            showPass = 1;
        }
        else {
            $(this).next('input').attr('type','password');
            $(this).removeClass('active');
            showPass = 0;
        }
        
    });


})(jQuery);


function searchByUsername() {
    var keyword = document.getElementById('searchInput').value;
    var resultsContainer = document.getElementById('searchResults');

    // Masquer les résultats si le champ est vide
    if (!keyword) {
        resultsContainer.style.display = 'none';
        resultsContainer.innerHTML = '';
        return;
    }

    // Afficher la zone de résultats
    resultsContainer.style.display = 'block';

    // Envoyer une requête AJAX à Flask pour récupérer les utilisateurs
    fetch(`/search_by_username?username=${keyword}`)
        .then(response => response.json())
        .then(data => {
            displaySearchResults(data);
        })
        .catch(error => console.error('Error:', error));
}

function displaySearchResults(results) {
    var resultsContainer = document.getElementById('searchResults');
    resultsContainer.innerHTML = ''; // Vider les anciens résultats

    if (results.length === 0) {
        resultsContainer.innerHTML = '<div>No results found</div>';
        return;
    }

    results.forEach(user => {
        var userElement = document.createElement('div');
        userElement.classList.add('user-item');
        userElement.innerHTML = `${user.username}`;

        // Ajouter un événement de clic pour remplir le champ de recherche
        userElement.onclick = function() {
            document.getElementById('searchInput').value = user.username;
            resultsContainer.style.display = 'none';  // Masquer les résultats après le clic
        };

        resultsContainer.appendChild(userElement);
    });
}
