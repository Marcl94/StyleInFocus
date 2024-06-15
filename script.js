document.getElementById("profile-icon").onclick = function () {
  document.getElementById("sidebar").style.width = "350px";
  document.getElementById("overlay").style.width = "100%";
};

document.querySelector(".close-btn").onclick = function () {
  document.getElementById("sidebar").style.width = "0";
  document.getElementById("overlay").style.width = "0";
};

document.getElementById("overlay").onclick = function () {
  document.getElementById("sidebar").style.width = "0";
  document.getElementById("overlay").style.width = "0";
};


function openLeftSidebar() {
  document.getElementById("leftSidebar").style.width = "380px";
}

function closeLeftSidebar() {
  document.getElementById("leftSidebar").style.width = "0";
}

// Fechar o sidebar ao clicar fora dele
document.addEventListener('click', function(event) {
  var sidebar = document.getElementById('leftSidebar');
  var btn = document.querySelector('.btn-filtrar');
  if (sidebar.style.width === "380px" && !sidebar.contains(event.target) && event.target !== btn) {
      closeLeftSidebar();
  }
});

function toggleDropdown(dropdownId) {
  const dropdown = document.getElementById(dropdownId);
  const arrow = dropdown.previousElementSibling.querySelector('.arrow');
  
  if (dropdown.style.display === 'block') {
      dropdown.style.display = 'none';
      arrow.classList.remove('up');
  } else {
      dropdown.style.display = 'block';
      arrow.classList.add('up');
  }
}

function toggleColor(color) {
  const button = document.querySelector(`.color-button[style*="${color}"]`);
  if (button.classList.contains('selected')) {
      button.classList.remove('selected');
  } else {
      button.classList.add('selected');
  }
}
//slide js 

let currentIndex = 0;
const items = document.querySelectorAll('.carousel-item');
const totalItems = items.length;
const itemsPerPage = 3;

const carousel = document.querySelector('.carousel');
const nextButton = document.getElementById('next');
const prevButton = document.getElementById('prev');

function updateCarousel() {
  const offset = -currentIndex * (100 / itemsPerPage);
  carousel.style.transform = `translateX(${offset}%)`;
}

function showNext() {
  if (currentIndex < Math.ceil(totalItems / itemsPerPage) - 1) {
    currentIndex++;
  } else {
    currentIndex = 0;
  }
  updateCarousel();
}

function showPrev() {
  if (currentIndex > 0) {
    currentIndex--;
  } else {
    currentIndex = Math.ceil(totalItems / itemsPerPage) - 1;
  }
  updateCarousel();
}

nextButton.addEventListener('click', showNext);
prevButton.addEventListener('click', showPrev);

setInterval(showNext, 8000); // Automatic slide every 3 seconds

// Initialize carousel
updateCarousel();

let currentSlide = 0;

function showSlide(index) {
    const slides = document.querySelectorAll('.slide-text-index');
    const totalSlides = slides.length;

    if (index >= totalSlides) {
        currentSlide = 0;
    } else if (index < 0) {
        currentSlide = totalSlides - 1;
    } else {
        currentSlide = index;
    }

    const newTransform = `translateX(${-currentSlide * 100}%)`;
    document.querySelector('.slides-text').style.transform = newTransform;
}

function nextSlide() {
    showSlide(currentSlide + 1);
}

function prevSlide() {
    showSlide(currentSlide - 1);
}

// Mostrar o primeiro slide
showSlide(currentSlide);

// Função para auto-slide
function startAutoSlide() {
  setInterval(nextSlide, 5000); // Muda de slide a cada 3 segundos
}

// Iniciar o auto-slide
startAutoSlide();

window.addEventListener('load', function() {
  document.getElementById('preloader').style.display = 'none';
});

// Código para exibir o preloader ao clicar em um link
document.addEventListener('DOMContentLoaded', function() {
  const links = document.querySelectorAll('a');
  links.forEach(link => {
      link.addEventListener('click', function(event) {
          if (!this.href.includes('#')) { // Evitar recarregar para links âncora
              document.getElementById('preloader').style.display = 'flex';
          }
      });
  });
});



var radio = document.querySelector('.manual-btn')
var cont = 1

document.getElementById('radio1').checked = true

setInterval(() => {
    proximaimg()
}, 5000)

function proximaimg(){
    cont++

    if(cont > 3 ){
        cont = 1
    }

    document.getElementById('radio'+cont).checked = true
}
