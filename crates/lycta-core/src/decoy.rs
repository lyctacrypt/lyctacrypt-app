use rand::seq::SliceRandom;
use rand::Rng;

use crate::hybrid::HybridKeyPair;
use crate::identity::Identity;
use crate::primitives::random_bytes;
use crate::ratchet::Ratchet;
use crate::vault::{Direction, HistoryEntry, Origin, Session, State};

const NOTES: &[&str] = &[
    "Mom",
    "Dad",
    "Emma",
    "Liam",
    "Sophie",
    "Noah",
    "Garage",
    "Book club",
    "Neighbor",
    "Roommate",
    "Grandma",
    "Jake",
    "Sarah",
    "Carpool",
    "Thursday football",
    "Mia",
    "Ethan",
    "Piano teacher",
];

const CONVERSATIONS: &[&[(bool, &str)]] = &[
    &[
        (false, "Coming over for lunch on Sunday?"),
        (true, "Yes, around 12:30. I'll bring dessert."),
        (false, "Great, see you Sunday!"),
    ],
    &[
        (true, "Did you finish the book?"),
        (false, "Almost, two chapters left."),
        (false, "Really good so far."),
        (true, "No spoilers then 😄"),
    ],
    &[
        (
            false,
            "The inspection is done, you can pick up the car tomorrow.",
        ),
        (true, "Thanks, I'll come by around 5."),
    ],
    &[
        (true, "Groceries tonight?"),
        (false, "Sure, we need milk and bread."),
        (true, "I'll grab some pasta too."),
    ],
    &[
        (false, "Match moved to next Thursday, the field is closed."),
        (true, "Too bad, thanks for letting me know."),
    ],
    &[
        (true, "Happy birthday! 🎂"),
        (false, "Thank you! Celebrating on Saturday if you're free."),
        (true, "Sounds good."),
    ],
    &[
        (false, "Could you water the plants while I'm away?"),
        (true, "Of course, leave the key with the concierge."),
        (false, "Thanks, you're a lifesaver."),
    ],
    &[
        (true, "Running 10 minutes late, the bus is slow."),
        (false, "No problem, I'm at the coffee shop."),
    ],
    &[
        (false, "Piano lesson moved to Wednesday 6 pm."),
        (true, "Got it, thanks."),
    ],
    &[
        (true, "Do you have the recipe for that pie?"),
        (false, "I'll send it tonight, it's really simple."),
    ],
];

pub fn populate(n: usize, conversations: bool) -> State {
    let mut rng = rand::thread_rng();
    let mut st = State::new();
    let n = n.clamp(1, 12);

    let mut notes: Vec<&str> = NOTES.to_vec();
    notes.shuffle(&mut rng);
    let mut convs: Vec<&[(bool, &str)]> = CONVERSATIONS.to_vec();
    convs.shuffle(&mut rng);

    for k in 0..n {
        let origin = if rng.gen_bool(0.5) {
            Origin::Invite
        } else {
            Origin::Request
        };
        let id = st.add_contact(Identity::generate().public(), origin);
        let c = st.contact_by_local(id).expect("just added");
        c.accepted = true;
        c.note = notes.get(k).map(|s| s.to_string());

        let root: [u8; 32] = random_bytes();
        let hka: [u8; 32] = random_bytes();
        let hkb: [u8; 32] = random_bytes();
        c.session = Some(Session {
            id: random_bytes(),
            ratchet: Ratchet::init_responder(&root, HybridKeyPair::generate(), &hka, &hkb),
        });
        c.peer_onion = Some(random_bytes());
        c.peer_auth = Some(random_bytes());
        if conversations {
            if let Some(conv) = convs.get(k % convs.len()) {
                for &(out, text) in conv.iter() {
                    let mut e = HistoryEntry::new(
                        if out { Direction::Out } else { Direction::In },
                        text.to_string(),
                        true,
                        None,
                    );
                    e.id = random_bytes();
                    c.push_history(e);
                }
            }
        }
    }
    st
}

#[cfg(test)]
mod tests {
    #[test]
    fn populates() {
        let st = super::populate(4, true);
        assert_eq!(st.contacts.len(), 4);
        assert!(st
            .contacts
            .iter()
            .all(|c| c.session.is_some() && c.accepted));
        assert!(st.contacts.iter().any(|c| !c.history.is_empty()));
        let empty = super::populate(2, false);
        assert!(empty.contacts.iter().all(|c| c.history.is_empty()));
    }
}
