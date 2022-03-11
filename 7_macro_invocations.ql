import cpp

from MacroInvocation mi
where mi.getMacro().getName() in ["ntohl","ntohll","ntohs"]
select mi