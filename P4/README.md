# Progetto P4 - Tunnel-based Forwarding & Proof of Transit

## Topologia aggiornata
```
h1--s1--s2--s3--s4--s6--h2
             \     /
              s5---
```
- Tunnel domain: s2, s3, s4, s5
- s1: ingress tunnel
- s6: egress tunnel

## File principali
- `lab.conf` — Topologia (aggiornata come sopra)
- `shared/tunnel.p4` — Programma P4 per tunnel, PoT, IPv4 fwd
- `sN/commands.txt` — Popolamento forwarding/tunnel di ogni switch
- `h1.startup`, `h2.startup` — Setup IP e route host

## Esecuzione (Kathara)
1. Avvia la rete:
   ```
kathara lstart
   ```
2. Verifica connettività:
   ```
kathara enter h1
ping 10.0.2.2
   ```
3. Osserva/controlla lo stato PoT dai log degli switch nel dominio tunnel (s2-s5)

## Note logiche
- I pacchetti da h1 a h2 sono incapsulati in tunnel da s1; attraversano s2, s3, s4, s5 (PoT update); decapsulati da s6.
- Gli switch/PoT possono aggiornare il campo pot_tag nel tunnel header secondo policy specifica (contatore, marker, hash…)
- Le porte degli switch nei commands.txt sono numerate secondo lab.conf, commentate.

## Personalizzazione
- Aggiorna i comandi nei file commands.txt secondo la numerazione effettiva delle MAC/interfacce.
- Aggiorna/personalizza `shared/tunnel.p4` per logica Proof of Transit complessa (esempio hash, autenticazione mark, ecc.).

---
Per dettagli e policy avanzate vedere la traccia Progetto P4.pdf allegata.
