This is the WebScarab OpenSource project, hosted at
http://www.owasp.org/development/webscarab.

It aims to become a tool that may be used automatically or interactively
to test web applications for their security.
WebScarab is written in 100% pure java and designed using a fairly clean
set of interfaces to allow for removal and substitution of existing
components, or addition of new analysis systems.

Basically WebScarab is divided into these parts:

 Framework - The framework is used to hold the various plugins that
             generate requests and analyse the responses. It also is
             responsible for managing the underlying per-conversation
             and per-URL data model, and making them available to the
             plugins as necessary.
   Plugins - WebScarab provides a number of plugins. Plugins are intended
             to generate requests (based on user interaction, or based
             on information gleaned by analysis of pages retrieved by
             other plugins). Once the request has been generated, and 
             the response retrieved from the server, that "conversation"
             is submitted to the Framework (via the Plug interface), and
             consequently passed to each and every plugin for processing.
       GUI - WebScarab provides a Swing User Interface, which hopefully
             offers an intuitive method of visualising and interacting
             with the web site under test. The developers have attempted
             to separate the plugins and frameworks from the User Interface
             implementation as far as possible, and developers should be
             able to implement alternative user interfaces without too
             much difficulty, without having to change the plugins themselves.

WebScarab has a number of existing plugins, but obviously, we are always 
working on developing new ones, and refining the existing ones. WebScarab
was designed in a way that should make adding new plugins a simple task,
without too many touch points in the existing code base. The current set
of plugins includes:

     Proxy - This plugin allows the operator to access the website using their
             web browser. All functionality of the web site should be
             available, including execution of JavaScript, and embedded 
             objects, since it all executes in the browser. The Proxy
             simply provides a method to observe the traffic between the 
             browser and the server, as well as modifying it in transit,
             to make changes to the data submitted which would ordinarily
             be difficult or impossible using the web browser itself.
    Spider - This plugin identifies new links from pages retrieved by plugins.
             Currently it is only able to examine HTML pages, but there is no
             reason why it should not be able to parse other content, such
             as Flash, or PDF, for example. It also does not understand
             JavaScript links, so the operator should be alert for the
             possibility of such links, and not assume that the site has been
             exhaustively reviewed.
    Manual - There is also a plugin that allows the operator to hand-craft
             a request, using raw HTTP, and retrieve the response. This is 
             similar to using netcat or even telnet to talk directly to 
             the webserver, but also adds the conversation to the data model.

The Proxy plugin has "intercept" capability, which allows WebScarab to make
changes to requests and responses "on-the-fly". There are a number of 
Proxy Plugin's provided with WebScarab, but again, the defined interface
is quite clean, and it should be straightforward to implement new ProxyPlugins.

WebScarab includes the following ProxyPlugins:

    Manual - This plugin pops up a window that contains the raw request or
             response, and allows the operator to edit it as desired.
    Hidden - This plugin changes forms with "hidden" input fields to make
             them visible in the browser, allowing the operator to see and
             change fields that the site designer may not expect.
     Cache - This plugin simply prevents the browser from using previously
             cached pages. This is useful if you are restarting a new session
             and only getting "empty" responses, since the browser has already
             seen the page.
    Cookie - This plugin synchronises cookies between a number of WebScarab 
             plugins, allowing the Proxy, Spider and Manual plugins to share
             and reuse cookies set by the servers.
 
// end of $Source: /cvsroot/owasp/webscarab/README,v $
