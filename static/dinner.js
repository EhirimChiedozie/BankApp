const logout = document.querySelector('#Logout');
function confirmLogout(){
    var result = confirm('Are you sure you want to logout?');
    if(result == false){
        event.preventDefault()
    }
}
logout.addEventListener('click', confirmLogout);


function addIdAttributes(item){
    let identity = document.querySelector(item);
    identity.style.width = '250px';
    identity.style.height = '90px'
    identity.style.fontSize = '30px';
    identity.style.fontFamily = 'monospace';
    identity.style.borderColor = 'sienna';
    identity.style.borderStyle = 'solid';
    identity.style.borderWidth = '5px';
    identity.style.borderRadius = '10px';
    identity.style.paddingLeft = '5px';
}

function addClassAttributes(item){
    let className = document.querySelector(item);
    className.style.hover.color = 'pink';
}

//addClassAttributes('.check-balance');
addIdAttributes('#Transfer');
addIdAttributes('#CheckBalance');
addIdAttributes('#Airtime');

const amount = document.querySelector('.acct-balance');
const jumbo = document.querySelector('.welcome');
const remark = document.createElement('h4')
jumbo.append(remark);
if(amount.innerHTML<=500){
    jumbo.style.backgroundColor = 'red';
    remark.innerText = 'Sapa don hook you';  
}
else if(amount.innerHTML>500 && amount.innerHTML<5000){
    jumbo.style.backgroundColor = 'sienna';
    remark.innerHTML = 'You just manage escape sapa. E fit still catch you. Hustle ooo'
}
else if(amount.innerHTML>=5000 && amount.innerHTML<50000){
    jumbo.style.backgroungColor = 'darkslategray';
    remark.innerHTML = 'A littlebit comfortable but still hustle';
}
else if(amount.innerHTML>50000){
    jumbo.style.backgroungColor = 'darkslateblue';
    remark.innerHTML = 'You fit relax';
}